function Invoke-SystemMicrosoftStoreChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/MicrosoftStore' -Message 'Starting Microsoft Store functional checks'

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'store-functional'
    Write-HeuristicDebug -Source 'System/MicrosoftStore' -Message 'Resolved store functional artifact' -Data ([ordered]@{
        Found = [bool]$artifact
    })
    if (-not $artifact) { return }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    Write-HeuristicDebug -Source 'System/MicrosoftStore' -Message 'Evaluating store payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if (-not $payload) { return }

    $propertyNames = $payload.PSObject.Properties | ForEach-Object { $_.Name }

    $storePackagePresent = $null
    if ($propertyNames -contains 'storePackagePresent') {
        $storePackagePresent = [bool]$payload.storePackagePresent
    }

    $installedLocationOk = $null
    if ($propertyNames -contains 'installedLocationOk') {
        $installedLocationOk = [bool]$payload.installedLocationOk
    }

    $appxManifestFound = $null
    if ($propertyNames -contains 'appxManifestFound') {
        $appxManifestFound = $payload.appxManifestFound
    }

    $services = @()
    if ($propertyNames -contains 'services') {
        if ($payload.services -is [System.Collections.IEnumerable] -and -not ($payload.services -is [string])) {
            $services = @($payload.services)
        } elseif ($payload.services) {
            $services = @($payload.services)
        }
    }

    $serviceMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($service in $services) {
        if (-not $service) { continue }
        if (-not $service.PSObject.Properties['name']) { continue }
        $serviceMap[$service.name] = $service
    }

    $proxy = $null
    if ($propertyNames -contains 'proxy') {
        $proxy = $payload.proxy
    }

    $reachability = @()
    if ($propertyNames -contains 'reachability') {
        if ($payload.reachability -is [System.Collections.IEnumerable] -and -not ($payload.reachability -is [string])) {
            $reachability = @($payload.reachability)
        } elseif ($payload.reachability) {
            $reachability = @($payload.reachability)
        }
    }

    $formatBool = {
        param($value)
        if ($value -eq $true) { return 'True' }
        if ($value -eq $false) { return 'False' }
        return 'Unknown'
    }

    $criticalServices = 'AppXSVC','ClipSVC','InstallService'
    $pathServices = 'DoSvc','wuauserv'

    $highReasons = New-Object System.Collections.Generic.List[string]
    $mediumReasons = New-Object System.Collections.Generic.List[string]

    $appxSvc = if ($serviceMap.ContainsKey('AppXSVC')) { $serviceMap['AppXSVC'] } else { $null }
    $storeNotApplicable = ($storePackagePresent -eq $false) -and (-not $appxSvc -or ((-not $appxSvc.startType) -and (-not $appxSvc.status)))
    if ($storeNotApplicable) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Store not applicable on this SKU' -Evidence 'Microsoft Store package absent and AppXSVC service missing.' -Subcategory 'Microsoft Store'
        return
    }

    if ($storePackagePresent -eq $false) {
        $highReasons.Add('Microsoft Store package missing or Get-AppxPackage returned no data.') | Out-Null
    } elseif ($storePackagePresent -eq $true) {
        if ($installedLocationOk -eq $false) {
            $highReasons.Add('Microsoft Store package InstalledLocation is missing or inaccessible.') | Out-Null
        }
        if ($appxManifestFound -eq $false) {
            $highReasons.Add('AppxManifest.xml for Microsoft Store was not found under C:\Program Files\WindowsApps.') | Out-Null
        }
    }

    foreach ($name in $criticalServices) {
        $entry = if ($serviceMap.ContainsKey($name)) { $serviceMap[$name] } else { $null }
        if (-not $entry) {
            $highReasons.Add("Critical service $name missing.") | Out-Null
            continue
        }

        $startType = if ($entry.PSObject.Properties['startType']) { [string]$entry.startType } else { $null }
        $status = if ($entry.PSObject.Properties['status']) { [string]$entry.status } else { $null }
        $startTypeNormalized = if ($startType) { $startType.ToLowerInvariant() } else { $null }
        $statusNormalized = if ($status) { $status.ToLowerInvariant() } else { $null }
        $startTypePolicyOk = $false
        if ($startTypeNormalized -in @('manual','auto','automatic')) { $startTypePolicyOk = $true }

        if (-not $startType -and -not $status) {
            $highReasons.Add("Critical service $name state unavailable.") | Out-Null
            continue
        }

        if ($startTypeNormalized -eq 'disabled') {
            $highReasons.Add("Critical service $name is disabled.") | Out-Null
            continue
        }

        if ($statusNormalized -eq 'stopped' -and -not $startTypePolicyOk) {
            $highReasons.Add("Critical service $name is stopped and not configured for Manual/Automatic start.") | Out-Null
        }
    }

    foreach ($name in $pathServices) {
        $entry = if ($serviceMap.ContainsKey($name)) { $serviceMap[$name] } else { $null }
        if (-not $entry) {
            $mediumReasons.Add("Service $name missing, delivery path unclear.") | Out-Null
            continue
        }

        $startType = if ($entry.PSObject.Properties['startType']) { [string]$entry.startType } else { $null }
        $status = if ($entry.PSObject.Properties['status']) { [string]$entry.status } else { $null }
        $startTypeNormalized = if ($startType) { $startType.ToLowerInvariant() } else { $null }
        $statusNormalized = if ($status) { $status.ToLowerInvariant() } else { $null }

        if ($startTypeNormalized -eq 'disabled') {
            $mediumReasons.Add("Service $name is disabled.") | Out-Null
            continue
        }

        if ($statusNormalized -eq 'stopped') {
            $mediumReasons.Add("Service $name is stopped.") | Out-Null
        }
    }

    $proxyIsDirect = $null
    $proxySummary = 'Unknown'
    if ($proxy) {
        if ($proxy.PSObject.Properties['isDirect']) { $proxyIsDirect = $proxy.isDirect }
        if ($proxy.PSObject.Properties['winhttp']) { $proxySummary = [string]$proxy.winhttp }
    }

    $failedEndpoints = @()
    $successfulTcp = 0
    $knownEndpoints = 0
    foreach ($entry in $reachability) {
        if (-not $entry) { continue }
        $dnsOk = if ($entry.PSObject.Properties['dnsOk']) { $entry.dnsOk } else { $null }
        $tcpOk = if ($entry.PSObject.Properties['tcp443Ok']) { $entry.tcp443Ok } else { $null }
        if ($tcpOk -eq $true) { $successfulTcp++ }
        if ($dnsOk -ne $null -or $tcpOk -ne $null) { $knownEndpoints++ }
        $dnsFailed = ($dnsOk -eq $false)
        $tcpFailed = ($tcpOk -eq $false)
        if ($dnsFailed -or $tcpFailed) {
            $failedEndpoints += $entry
        }
    }

    $failedCount = $failedEndpoints.Count
    $proxyNonDirect = ($proxyIsDirect -eq $false) -or (($proxySummary -and $proxySummary -notin @('Direct','Unknown')))
    if ($proxyNonDirect -and $failedCount -gt 0) {
        $mediumReasons.Add('WinHTTP proxy is non-direct and Store endpoints show connectivity failures.') | Out-Null
    }

    if ($failedCount -ge 2) {
        $mediumReasons.Add('At least two Microsoft Store endpoints failed DNS or TCP reachability checks.') | Out-Null
    }

    $evidenceLines = New-Object System.Collections.Generic.List[string]
    $evidenceLines.Add("storePackagePresent=$((& $formatBool $storePackagePresent))") | Out-Null
    $evidenceLines.Add("installedLocationOk=$((& $formatBool $installedLocationOk))") | Out-Null
    $manifestStatus = if ($null -eq $appxManifestFound) { 'Unknown' } elseif ($appxManifestFound -eq $true) { 'True' } else { 'False' }
    $evidenceLines.Add("appxManifestFound=$manifestStatus") | Out-Null

    foreach ($name in $criticalServices + $pathServices) {
        $entry = if ($serviceMap.ContainsKey($name)) { $serviceMap[$name] } else { $null }
        if ($entry) {
            $startType = if ($entry.PSObject.Properties['startType']) { [string]$entry.startType } else { 'Unknown' }
            $status = if ($entry.PSObject.Properties['status']) { [string]$entry.status } else { 'Unknown' }
            $evidenceLines.Add("$name: StartType=$startType; Status=$status") | Out-Null
        } else {
            $evidenceLines.Add("$name: StartType=Unknown; Status=Unknown") | Out-Null
        }
    }

    $evidenceLines.Add("proxy=$proxySummary") | Out-Null

    if ($reachability.Count -gt 0) {
        foreach ($entry in $reachability) {
            if (-not $entry -or -not $entry.PSObject.Properties['host']) { continue }
            $dnsOk = if ($entry.PSObject.Properties['dnsOk']) { $entry.dnsOk } else { $null }
            $tcpOk = if ($entry.PSObject.Properties['tcp443Ok']) { $entry.tcp443Ok } else { $null }
            $evidenceLines.Add("$($entry.host): DNS=$((& $formatBool $dnsOk)); TCP443=$((& $formatBool $tcpOk))") | Out-Null
        }
    }

    Add-CategoryCheck -CategoryResult $Result -Name 'Store package present' -Status (& $formatBool $storePackagePresent)
    Add-CategoryCheck -CategoryResult $Result -Name 'Installed location OK' -Status (& $formatBool $installedLocationOk)
    Add-CategoryCheck -CategoryResult $Result -Name 'AppxManifest located' -Status $manifestStatus
    foreach ($name in $criticalServices + $pathServices) {
        $entry = if ($serviceMap.ContainsKey($name)) { $serviceMap[$name] } else { $null }
        $startType = if ($entry -and $entry.PSObject.Properties['startType']) { [string]$entry.startType } else { 'Unknown' }
        $status = if ($entry -and $entry.PSObject.Properties['status']) { [string]$entry.status } else { 'Unknown' }
        Add-CategoryCheck -CategoryResult $Result -Name "Service $name" -Status "$startType / $status"
    }

    if ($reachability.Count -gt 0) {
        foreach ($entry in $reachability) {
            if (-not $entry -or -not $entry.PSObject.Properties['host']) { continue }
            $dnsOk = if ($entry.PSObject.Properties['dnsOk']) { $entry.dnsOk } else { $null }
            $tcpOk = if ($entry.PSObject.Properties['tcp443Ok']) { $entry.tcp443Ok } else { $null }
            Add-CategoryCheck -CategoryResult $Result -Name "Reachability $($entry.host)" -Status "DNS=$((& $formatBool $dnsOk)); TCP443=$((& $formatBool $tcpOk))"
        }
    }

    $evidence = $evidenceLines -join "`n"

    if ($highReasons.Count -gt 0) {
        $reasonText = ($highReasons + $mediumReasons) -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Microsoft Store functional checks failing' -Evidence (($reasonText, '', $evidence) -join "`n") -Subcategory 'Microsoft Store'
    } elseif ($mediumReasons.Count -gt 0) {
        $reasonText = $mediumReasons -join "`n"
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Microsoft Store functional checks failing' -Evidence (($reasonText, '', $evidence) -join "`n") -Subcategory 'Microsoft Store'
    } else {
        $totalReachability = if ($knownEndpoints -gt 0) { $knownEndpoints } elseif ($reachability -and ($reachability.Count -gt 0)) { $reachability.Count } else { 0 }
        $tcpSummary = if ($totalReachability -gt 0) { "$successfulTcp/$totalReachability" } else { "$successfulTcp/?" }
        $successSummary = "storePackagePresent=true; services OK (AppXSVC/ClipSVC/InstallService Running or Manual); proxy=$proxySummary; endpoints reachable ($tcpSummary TCP 443 OK)"
        Add-CategoryNormal -CategoryResult $Result -Title 'Microsoft Store functional checks passed' -Evidence (($successSummary, '', $evidence) -join "`n") -Subcategory 'Microsoft Store'
    }
}
