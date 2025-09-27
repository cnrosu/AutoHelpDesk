<#!
.SYNOPSIS
    Service health heuristics reviewing stopped automatic services and query errors.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Normalize-ServiceStateValue {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    if ($lower -like 'run*') { return 'running' }
    if ($lower -like 'stop*') { return 'stopped' }
    return 'other'
}

function Normalize-ServiceStartValue {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    if ($lower -like 'auto*' -and $lower -like '*delay*') { return 'automatic-delayed' }
    if ($lower -like 'auto*') { return 'automatic' }
    if ($lower -like 'manual*') { return 'manual' }
    if ($lower -like 'disabled*') { return 'disabled' }
    return 'other'
}

function Get-ServiceStateInfo {
    param(
        $Lookup,
        [string]$Name
    )

    if (-not $Lookup -or -not $Lookup.ContainsKey($Name)) {
        return [pscustomobject]@{
            Exists              = $false
            Name                = $Name
            DisplayName         = $Name
            Status              = 'Unknown'
            StatusNormalized    = 'unknown'
            StartMode           = 'Unknown'
            StartModeNormalized = 'unknown'
        }
    }

    $service = $Lookup[$Name]
    $status = 'Unknown'
    if ($service.PSObject.Properties['State']) { $status = [string]$service.State }
    elseif ($service.PSObject.Properties['Status']) { $status = [string]$service.Status }

    $startMode = 'Unknown'
    if ($service.PSObject.Properties['StartMode']) { $startMode = [string]$service.StartMode }
    elseif ($service.PSObject.Properties['StartType']) { $startMode = [string]$service.StartType }

    $displayName = if ($service.PSObject.Properties['DisplayName']) { [string]$service.DisplayName } else { $Name }

    return [pscustomobject]@{
        Exists              = $true
        Name                = $Name
        DisplayName         = $displayName
        Status              = if ($status) { $status } else { 'Unknown' }
        StatusNormalized    = Normalize-ServiceStateValue -Value $status
        StartMode           = if ($startMode) { $startMode } else { 'Unknown' }
        StartModeNormalized = Normalize-ServiceStartValue -Value $startMode
    }
}

function Get-DevicePlatformInfo {
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

function Get-SystemProxyInfo {
    param($Context)

    $hasSystemProxy = $false
    $proxyEvidence = $null

    $proxyArtifact = Get-AnalyzerArtifact -Context $Context -Name 'proxy'
    if ($proxyArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $proxyArtifact)
        if ($payload -and $payload.WinHttp) {
            if ($payload.WinHttp -is [System.Collections.IEnumerable] -and -not ($payload.WinHttp -is [string])) {
                $proxyEvidence = ($payload.WinHttp -join "`n").Trim()
            } else {
                $proxyEvidence = ([string]$payload.WinHttp).Trim()
            }

            if ($proxyEvidence -and ($proxyEvidence -notmatch '(?i)direct\s+access')) {
                $hasSystemProxy = $true
            }
        }
    }

    return [pscustomobject]@{
        HasSystemProxy = $hasSystemProxy
        Evidence       = $proxyEvidence
    }
}

function Invoke-ServicesHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Services'

    $platform = Get-DevicePlatformInfo -Context $Context
    $isServer = ($platform.IsWindowsServer -eq $true)
    $isWorkstation = ($platform.IsWorkstation -eq $true)
    $proxyInfo = Get-SystemProxyInfo -Context $Context

    $servicesArtifact = Get-AnalyzerArtifact -Context $Context -Name 'services'
    if ($servicesArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $servicesArtifact)
        if ($payload -and $payload.Services -and -not $payload.Services.Error) {
            $services = $payload.Services
            if ($services -is [System.Collections.IEnumerable] -and -not ($services -is [string])) {
                $services = @($services)
            } else {
                $services = @($services)
            }

            $lookup = @{}
            foreach ($service in $services) {
                if (-not $service) { continue }
                if ($service.PSObject.Properties['Name']) {
                    $lookup[[string]$service.Name] = $service
                }
            }

            $wsearch = Get-ServiceStateInfo -Lookup $lookup -Name 'WSearch'
            if (-not $wsearch.Exists) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Windows Search service missing' -Evidence 'Service entry not found; search and Outlook indexing will fail.' -Subcategory 'Windows Search Service'
            } elseif ($wsearch.StatusNormalized -eq 'running') {
                Add-CategoryNormal -CategoryResult $result -Title 'Windows Search service running' -Evidence ("Status: {0}; StartType: {1}" -f $wsearch.Status, $wsearch.StartMode) -Subcategory 'Windows Search Service'
            } else {
                $title = "Windows Search service not running (Status: {0}; StartType: {1})." -f $wsearch.Status, $wsearch.StartMode
                if ($wsearch.StartModeNormalized -eq 'manual') {
                    if ($isWorkstation) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Windows Search set to Manual and stopped' -Evidence $title -Subcategory 'Windows Search Service'
                    } elseif ($isServer) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Windows Search manual start and currently stopped' -Evidence $title -Subcategory 'Windows Search Service'
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Windows Search manual start and currently stopped' -Evidence $title -Subcategory 'Windows Search Service'
                    }
                } elseif ($wsearch.StartModeNormalized -eq 'disabled') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Windows Search disabled' -Evidence $title -Subcategory 'Windows Search Service'
                } else {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Windows Search not running' -Evidence $title -Subcategory 'Windows Search Service'
                }
            }

            $dnsCache = Get-ServiceStateInfo -Lookup $lookup -Name 'Dnscache'
            if (-not $dnsCache.Exists) {
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'DNS Client (Dnscache) service missing' -Evidence 'Service entry not found; DNS resolution will fail.' -Subcategory 'DNS Client Service'
            } elseif ($dnsCache.StatusNormalized -eq 'running') {
                Add-CategoryNormal -CategoryResult $result -Title 'DNS Client service running' -Evidence ("Status: {0}; StartType: {1}" -f $dnsCache.Status, $dnsCache.StartMode) -Subcategory 'DNS Client Service'
            } else {
                $dnsTitle = "DNS Client service not running (Status: {0}; StartType: {1})." -f $dnsCache.Status, $dnsCache.StartMode
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'DNS Client service offline — name resolution will break' -Evidence $dnsTitle -Subcategory 'DNS Client Service'
            }

            $nla = Get-ServiceStateInfo -Lookup $lookup -Name 'NlaSvc'
            if (-not $nla.Exists) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Network Location Awareness service missing' -Evidence 'Service entry not found; network profile detection will fail.' -Subcategory 'Network Location Awareness'
            } elseif ($nla.StatusNormalized -eq 'running') {
                Add-CategoryNormal -CategoryResult $result -Title 'Network Location Awareness running' -Evidence ("Status: {0}; StartType: {1}" -f $nla.Status, $nla.StartMode) -Subcategory 'Network Location Awareness'
            } else {
                $nlaEvidence = "Status: {0}; StartType: {1}" -f $nla.Status, $nla.StartMode
                if ($nla.StartModeNormalized -eq 'manual' -and $isWorkstation) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Network Location Awareness set to Manual and stopped' -Evidence $nlaEvidence -Subcategory 'Network Location Awareness'
                } else {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Network Location Awareness service not running' -Evidence $nlaEvidence -Subcategory 'Network Location Awareness'
                }
            }

            $lanmanWk = Get-ServiceStateInfo -Lookup $lookup -Name 'LanmanWorkstation'
            if (-not $lanmanWk.Exists) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Workstation (LanmanWorkstation) service missing' -Evidence 'Service entry not found; SMB client functionality unavailable.' -Subcategory 'Workstation Service'
            } elseif ($lanmanWk.StatusNormalized -eq 'running') {
                Add-CategoryNormal -CategoryResult $result -Title 'Workstation service running' -Evidence ("Status: {0}; StartType: {1}" -f $lanmanWk.Status, $lanmanWk.StartMode) -Subcategory 'Workstation Service'
            } else {
                $lanmanEvidence = "Status: {0}; StartType: {1}" -f $lanmanWk.Status, $lanmanWk.StartMode
                $lanmanTitle = if ($lanmanWk.StartModeNormalized -eq 'disabled') { 'Workstation service disabled — SMB connectivity broken' } else { 'Workstation service stopped — SMB connectivity broken' }
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title $lanmanTitle -Evidence $lanmanEvidence -Subcategory 'Workstation Service'
            }

            $spooler = Get-ServiceStateInfo -Lookup $lookup -Name 'Spooler'
            if (-not $spooler.Exists) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Print Spooler service missing' -Evidence 'Service entry not found; printing features unavailable.' -Subcategory 'Print Spooler Service'
            } elseif ($spooler.StatusNormalized -eq 'running') {
                if ($isWorkstation) {
                    $title = 'Print Spooler running — disable if this workstation does not require printing (PrintNightmare risk).'
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence ("Status: {0}; StartType: {1}" -f $spooler.Status, $spooler.StartMode) -Subcategory 'Print Spooler Service'
                } else {
                    Add-CategoryNormal -CategoryResult $result -Title 'Print Spooler running' -Evidence ("Status: {0}; StartType: {1}" -f $spooler.Status, $spooler.StartMode) -Subcategory 'Print Spooler Service'
                }
            } else {
                $note = if ($isWorkstation) { 'PrintNightmare guidance: disable spooler unless required.' } else { 'Printing functionality will be unavailable while stopped.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Print Spooler not running' -Evidence ("Status: {0}; StartType: {1}; Note: {2}" -f $spooler.Status, $spooler.StartMode, $note) -Subcategory 'Print Spooler Service'
            }

            $rpc = Get-ServiceStateInfo -Lookup $lookup -Name 'RpcSs'
            if (-not $rpc.Exists) {
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'RPC (RpcSs) service missing' -Evidence 'Service entry not found; Windows cannot operate without RPC.' -Subcategory 'RPC Services'
            } elseif ($rpc.StatusNormalized -eq 'running') {
                Add-CategoryNormal -CategoryResult $result -Title 'RPC (RpcSs) service running' -Evidence ("Status: {0}; StartType: {1}" -f $rpc.Status, $rpc.StartMode) -Subcategory 'RPC Services'
            } else {
                $rpcEvidence = "Status: {0}; StartType: {1}" -f $rpc.Status, $rpc.StartMode
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'RPC (RpcSs) service not running — system instability expected' -Evidence $rpcEvidence -Subcategory 'RPC Services'
            }

            $rpcMapper = Get-ServiceStateInfo -Lookup $lookup -Name 'RpcEptMapper'
            if (-not $rpcMapper.Exists) {
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'RPC Endpoint Mapper service missing' -Evidence 'Service entry not found; RPC endpoint resolution unavailable.' -Subcategory 'RPC Services'
            } elseif ($rpcMapper.StatusNormalized -eq 'running') {
                Add-CategoryNormal -CategoryResult $result -Title 'RPC Endpoint Mapper running' -Evidence ("Status: {0}; StartType: {1}" -f $rpcMapper.Status, $rpcMapper.StartMode) -Subcategory 'RPC Services'
            } else {
                $rpcMapperEvidence = "Status: {0}; StartType: {1}" -f $rpcMapper.Status, $rpcMapper.StartMode
                Add-CategoryIssue -CategoryResult $result -Severity 'critical' -Title 'RPC Endpoint Mapper not running — RPC clients will fail' -Evidence $rpcMapperEvidence -Subcategory 'RPC Services'
            }

            $winHttp = Get-ServiceStateInfo -Lookup $lookup -Name 'WinHttpAutoProxySvc'
            if (-not $winHttp.Exists) {
                if ($proxyInfo.HasSystemProxy) {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'WinHTTP Auto Proxy service missing while a proxy is configured' -Evidence $proxyInfo.Evidence -Subcategory 'WinHTTP Auto Proxy Service'
                } else {
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'WinHTTP Auto Proxy service missing' -Subcategory 'WinHTTP Auto Proxy Service'
                }
            } elseif ($winHttp.StatusNormalized -eq 'running') {
                $evidence = "Status: {0}; StartType: {1}" -f $winHttp.Status, $winHttp.StartMode
                if ($winHttp.StartModeNormalized -eq 'manual' -and -not $proxyInfo.HasSystemProxy) {
                    $evidence = "{0}; Manual trigger start with no system proxy configured." -f $evidence
                }
                Add-CategoryNormal -CategoryResult $result -Title 'WinHTTP Auto Proxy service running' -Evidence $evidence -Subcategory 'WinHTTP Auto Proxy Service'
            } else {
                $winHttpEvidence = "Status: {0}; StartType: {1}" -f $winHttp.Status, $winHttp.StartMode
                if ($proxyInfo.Evidence) {
                    $winHttpEvidence = "{0}`nProxy: {1}" -f $winHttpEvidence, $proxyInfo.Evidence
                }

                if ($winHttp.StartModeNormalized -eq 'manual') {
                    if ($proxyInfo.HasSystemProxy) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'WinHTTP Auto Proxy manual start while a proxy is configured' -Evidence $winHttpEvidence -Subcategory 'WinHTTP Auto Proxy Service'
                    } else {
                        Add-CategoryNormal -CategoryResult $result -Title 'WinHTTP Auto Proxy in manual mode with no proxy configured' -Evidence $winHttpEvidence -Subcategory 'WinHTTP Auto Proxy Service'
                    }
                } elseif ($winHttp.StartModeNormalized -in @('automatic','automatic-delayed')) {
                    $severity = if ($proxyInfo.HasSystemProxy) { 'high' } else { 'medium' }
                    Add-CategoryIssue -CategoryResult $result -Severity $severity -Title 'WinHTTP Auto Proxy service not running' -Evidence $winHttpEvidence -Subcategory 'WinHTTP Auto Proxy Service'
                } elseif ($winHttp.StartModeNormalized -eq 'disabled') {
                    if ($proxyInfo.HasSystemProxy) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'WinHTTP Auto Proxy disabled while a proxy is configured' -Evidence $winHttpEvidence -Subcategory 'WinHTTP Auto Proxy Service'
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'WinHTTP Auto Proxy disabled' -Evidence $winHttpEvidence -Subcategory 'WinHTTP Auto Proxy Service'
                    }
                } else {
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'WinHTTP Auto Proxy service in unexpected state' -Evidence $winHttpEvidence -Subcategory 'WinHTTP Auto Proxy Service'
                }
            }

            $bits = Get-ServiceStateInfo -Lookup $lookup -Name 'BITS'
            if (-not $bits.Exists) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'BITS service missing' -Evidence 'Background transfers for Windows Update, AV, and Office will fail.' -Subcategory 'BITS Service'
            } else {
                $bitsEvidence = "Status: {0}; StartType: {1}" -f $bits.Status, $bits.StartMode
                if ($bits.StatusNormalized -eq 'running' -and $bits.StartModeNormalized -notin @('manual','disabled')) {
                    Add-CategoryNormal -CategoryResult $result -Title 'BITS running' -Evidence $bitsEvidence -Subcategory 'BITS Service'
                }

                if ($bits.StartModeNormalized -eq 'disabled') {
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'BITS disabled — background transfers stopped' -Evidence $bitsEvidence -Subcategory 'BITS Service'
                } elseif ($bits.StartModeNormalized -in @('automatic','automatic-delayed')) {
                    if ($bits.StatusNormalized -ne 'running') {
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'BITS automatic but not running' -Evidence $bitsEvidence -Subcategory 'BITS Service'
                    }
                } elseif ($bits.StartModeNormalized -eq 'manual') {
                    if ($isWorkstation) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'BITS configured for manual start on workstation' -Evidence $bitsEvidence -Subcategory 'BITS Service'
                    } elseif ($bits.StatusNormalized -ne 'running') {
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'BITS manual start and currently stopped' -Evidence $bitsEvidence -Subcategory 'BITS Service'
                    }
                }
            }

            $clickToRun = Get-ServiceStateInfo -Lookup $lookup -Name 'ClickToRunSvc'
            if ($clickToRun.Exists) {
                $clickEvidence = "Status: {0}; StartType: {1}" -f $clickToRun.Status, $clickToRun.StartMode
                if ($clickToRun.StatusNormalized -eq 'running') {
                    Add-CategoryNormal -CategoryResult $result -Title 'Office Click-to-Run service running' -Evidence $clickEvidence -Subcategory 'Office Click-to-Run'
                }

                if ($clickToRun.StartModeNormalized -in @('automatic','automatic-delayed')) {
                    if ($clickToRun.StatusNormalized -ne 'running') {
                        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Office Click-to-Run automatic but not running' -Evidence $clickEvidence -Subcategory 'Office Click-to-Run'
                    }
                } elseif ($clickToRun.StartModeNormalized -eq 'manual' -or $clickToRun.StartModeNormalized -eq 'disabled') {
                    if ($isWorkstation) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Office Click-to-Run not set to automatic on workstation' -Evidence $clickEvidence -Subcategory 'Office Click-to-Run'
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Office Click-to-Run manual/disabled on server' -Evidence $clickEvidence -Subcategory 'Office Click-to-Run'
                    }
                }
            }

            $stoppedAuto = $services | Where-Object {
                ($_.StartMode -eq 'Auto' -or $_.StartType -eq 'Automatic') -and ($_.State -ne 'Running' -and $_.Status -ne 'Running')
            }
            if ($stoppedAuto.Count -gt 0) {
                $summary = $stoppedAuto | Select-Object -First 5 | ForEach-Object { "{0} ({1})" -f $_.DisplayName, ($_.State ? $_.State : $_.Status) }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Automatic services not running' -Evidence ($summary -join "`n") -Subcategory 'Service Inventory'
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Automatic services running'
            }
        } elseif ($payload.Services.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Unable to query services' -Evidence $payload.Services.Error -Subcategory 'Service Inventory'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Services artifact missing' -Subcategory 'Collection'
    }

    return $result
}
