<#!
.SYNOPSIS
    Evaluates Autodiscover DNS and SCP posture so Outlook can auto-configure Exchange profiles reliably.
#>

function ConvertTo-AutodiscoverArray {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value)
    }

    return @($Value)
}

function Get-AutodiscoverJoinContext {
    param([Parameter(Mandatory)]$Context)

    $identity = Get-MsinfoSystemIdentity -Context $Context
    $isDomainJoined = $null
    if ($identity -and $identity.PSObject.Properties['PartOfDomain']) {
        try { $isDomainJoined = [bool]$identity.PartOfDomain } catch { $isDomainJoined = $null }
    }

    $dsRegText = Get-DsRegCmdText -Context $Context
    $isAzureAdJoined = $false
    if ($dsRegText) {
        $isAzureAdJoined = Get-AzureAdJoinState -DsRegCmdOutput $dsRegText
    }

    $joinState = 'Workgroup'
    if ($isDomainJoined -eq $true -and $isAzureAdJoined -eq $true) {
        $joinState = 'HAADJ'
    } elseif ($isDomainJoined -eq $true) {
        $joinState = 'AD-joined'
    } elseif ($isAzureAdJoined -eq $true) {
        $joinState = 'AADJ'
    }

    return [pscustomobject]@{
        JoinState       = $joinState
        IsDomainJoined  = $isDomainJoined
        IsAzureAdJoined = $isAzureAdJoined
    }
}

function ConvertTo-AutodiscoverLookupMap {
    param([object]$Lookups)

    $map = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($lookup in (ConvertTo-AutodiscoverArray -Value $Lookups)) {
        if (-not $lookup) { continue }
        $label = $lookup.Label
        if ([string]::IsNullOrWhiteSpace($label)) { continue }
        $map[$label] = $lookup
    }

    return $map
}

function Test-AutodiscoverCnameNxDomain {
    param($Lookup)

    if (-not $Lookup) { return $false }
    if ($Lookup.Success -eq $true) { return $false }
    $errorText = if ($Lookup.PSObject.Properties['Error']) { [string]$Lookup.Error } else { '' }
    if (-not $errorText) { return $false }

    return (
        $errorText -match '(?i)does not exist' -or
        $errorText -match '(?i)non-existent domain' -or
        $errorText -match '(?i)no cname records'
    )
}

function Update-AutodiscoverNxDomainHistory {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter()][bool]$IsNxDomain
    )

    $commandsAvailable = (
        (Get-Command -Name 'Test-AhdCacheItem' -ErrorAction SilentlyContinue) -and
        (Get-Command -Name 'Get-AhdCacheValue' -ErrorAction SilentlyContinue) -and
        (Get-Command -Name 'Set-AhdCacheValue' -ErrorAction SilentlyContinue)
    )

    $history = @()
    $consecutive = $false

    if ($commandsAvailable) {
        $keyDomain = $Domain.ToLowerInvariant()
        $cacheKey = "AutodiscoverDns::${keyDomain}::CnameNxDomain"
        if (Test-AhdCacheItem -Key $cacheKey) {
            $cached = Get-AhdCacheValue -Key $cacheKey
            if ($cached -is [System.Collections.IEnumerable]) {
                $history = @($cached | Where-Object { $_ -is [bool] })
            }
        }

        $history = @($history + $IsNxDomain)
        if ($history.Count -gt 2) {
            $history = $history[($history.Count - 2) .. ($history.Count - 1)]
        }

        try {
            Set-AhdCacheValue -Key $cacheKey -Value $history -SlidingExpiration ([System.TimeSpan]::FromHours(12))
        } catch {
        }

        if ($history.Count -ge 2) {
            $consecutive = ($history[-1] -eq $true -and $history[-2] -eq $true)
        }
    }

    return [pscustomobject]@{
        History     = $history
        Consecutive = $consecutive
    }
}

function Get-AutodiscoverHostFromUrl {
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }

    $candidate = $Url.Trim()
    if (-not $candidate) { return $null }

    if ($candidate -notmatch '^[a-z][a-z0-9+\.-]*://') {
        $candidate = "https://$candidate"
    }

    try {
        $uri = [System.Uri]$candidate
        if ($uri.Host) { return $uri.Host.ToLowerInvariant() }
    } catch {
    }

    return $null
}

function Get-AutodiscoverScpData {
    param([Parameter(Mandatory)]$Context)

    $data = [ordered]@{
        Entries = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
        Errors  = New-Object System.Collections.Generic.List[string]
    }

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-connectivity'
    if (-not $artifact) {
        return [pscustomobject]$data
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not ($payload -and $payload.Autodiscover)) {
        return [pscustomobject]$data
    }

    $scp = $payload.Autodiscover
    $directoryEntries = $null
    if ($scp.PSObject.Properties['Directory']) { $directoryEntries = $scp.Directory }

    foreach ($entry in (ConvertTo-AutodiscoverArray -Value $directoryEntries)) {
        if (-not $entry) { continue }
        if ($entry.PSObject.Properties['Error'] -and $entry.Error) {
            $data.Errors.Add([string]$entry.Error) | Out-Null
            continue
        }

        $domain = $null
        if ($entry.PSObject.Properties['Domain'] -and $entry.Domain) {
            $domain = [string]$entry.Domain
        }

        if (-not $domain -and $entry.PSObject.Properties['Keywords']) {
            foreach ($keyword in (ConvertTo-AutodiscoverArray -Value $entry.Keywords)) {
                if (-not $keyword) { continue }
                $text = [string]$keyword
                if (-not $text) { continue }
                if ($text -match '^(?i)Domain=(.+)$') {
                    $domain = $matches[1]
                    break
                }
            }
        }

        $url = $null
        if ($entry.PSObject.Properties['Url'] -and $entry.Url) {
            $url = [string]$entry.Url
        } elseif ($entry.PSObject.Properties['serviceBindingInformation'] -and $entry.serviceBindingInformation) {
            $url = [string]$entry.serviceBindingInformation
        }

        $host = Get-AutodiscoverHostFromUrl -Url $url
        $site = $null
        if ($entry.PSObject.Properties['Site'] -and $entry.Site) {
            $site = [string]$entry.Site
        }

        $formatted = [pscustomobject]@{
            Domain = $domain
            Url    = $url
            Host   = $host
            Site   = $site
            Raw    = $entry
        }

        $domainKey = if ($domain) { $domain } else { '*' }
        if (-not $data.Entries.ContainsKey($domainKey)) {
            $data.Entries[$domainKey] = New-Object System.Collections.Generic.List[object]
        }

        $data.Entries[$domainKey].Add($formatted) | Out-Null
    }

    return [pscustomobject]@{
        Entries = $data.Entries
        Errors  = $data.Errors.ToArray()
    }
}

function Get-AutodiscoverTopologyInfo {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)]$LookupMap
    )

    $result = [ordered]@{
        Topology          = 'Unknown'
        HasCname          = $false
        HasMsCname        = $false
        CnameSuccess      = $false
        CnameTargets      = @()
        CnameError        = $null
        HasSrv            = $false
        HasSrv443         = $false
        SrvTargets        = @()
        SrvRecords        = @()
        HasARecord        = $false
        ARecordAddresses  = @()
        HasMsMx           = $false
        MxTargets         = @()
        LookupMap         = $LookupMap
    }

    $cname = if ($LookupMap.ContainsKey('Autodiscover')) { $LookupMap['Autodiscover'] } else { $null }
    if ($cname) {
        if ($cname.PSObject.Properties['Error']) { $result.CnameError = $cname.Error }
        if ($cname.Success -eq $true) {
            $result.CnameSuccess = $true
            $targets = @($cname.Targets | Where-Object { $_ })
            $result.CnameTargets = $targets
            if ($targets.Count -gt 0) { $result.HasCname = $true }
            if ($targets | Where-Object { $_ -match '(?i)autodiscover(-s)?\.outlook\.com$' }) {
                $result.HasMsCname = $true
            }
        }
    }

    $srvRecords = @()
    $srv = if ($LookupMap.ContainsKey('AutodiscoverSrv')) { $LookupMap['AutodiscoverSrv'] } else { $null }
    if ($srv -and $srv.Success -eq $true) {
        $srvTargets = New-Object System.Collections.Generic.List[string]
        foreach ($record in (ConvertTo-AutodiscoverArray -Value $srv.Records)) {
            if (-not $record) { continue }
            $target = $null
            if ($record.PSObject.Properties['Target'] -and $record.Target) {
                $target = [string]$record.Target
                $srvTargets.Add($target.ToLowerInvariant()) | Out-Null
            }
            if ($record.PSObject.Properties['Port'] -and $record.Port -eq 443) {
                $result.HasSrv443 = $true
            }
            $srvRecords += [pscustomobject]@{
                Priority = if ($record.PSObject.Properties['Priority']) { $record.Priority } else { $null }
                Weight   = if ($record.PSObject.Properties['Weight']) { $record.Weight } else { $null }
                Port     = if ($record.PSObject.Properties['Port']) { $record.Port } else { $null }
                Target   = $target
            }
        }
        if ($srvTargets.Count -gt 0) {
            $result.HasSrv = $true
            $result.SrvTargets = $srvTargets.ToArray()
            $result.SrvRecords = $srvRecords
        }
    }

    $addresses = New-Object System.Collections.Generic.List[string]
    foreach ($label in @('AutodiscoverA','AutodiscoverAAAA')) {
        if (-not $LookupMap.ContainsKey($label)) { continue }
        $record = $LookupMap[$label]
        if ($record -and $record.Success -eq $true) {
            foreach ($address in (ConvertTo-AutodiscoverArray -Value $record.Addresses)) {
                if (-not $address) { continue }
                $addresses.Add([string]$address) | Out-Null
            }
        }
    }
    if ($addresses.Count -gt 0) {
        $result.HasARecord = $true
        $result.ARecordAddresses = $addresses.ToArray()
    }

    $mxTargets = New-Object System.Collections.Generic.List[string]
    $mx = if ($LookupMap.ContainsKey('Mx')) { $LookupMap['Mx'] } else { $null }
    if ($mx -and $mx.Success -eq $true) {
        foreach ($record in (ConvertTo-AutodiscoverArray -Value $mx.Records)) {
            if (-not $record) { continue }
            $target = $null
            if ($record.PSObject.Properties['Target'] -and $record.Target) {
                $target = [string]$record.Target
                $mxTargets.Add($target) | Out-Null
                if ($target -match '(?i)\.mail\.protection\.outlook\.com$') {
                    $result.HasMsMx = $true
                }
            }
        }
        $result.MxTargets = $mxTargets.ToArray()
    }

    $exoSignal = ($result.HasMsCname -or $result.HasMsMx)
    $onPremSignal = $false
    if ($result.HasARecord) { $onPremSignal = $true }
    if ($result.HasSrv -and $result.SrvTargets.Count -gt 0) { $onPremSignal = $true }
    if ($result.HasCname -and -not $result.HasMsCname) { $onPremSignal = $true }

    if ($result.HasMsCname -and $onPremSignal) {
        $result.Topology = 'Hybrid'
    } elseif ($exoSignal) {
        $result.Topology = 'EXO'
    } elseif ($onPremSignal) {
        $result.Topology = 'On-prem'
    }

    return [pscustomobject]$result
}

function Get-AutodiscoverIssueMetadata {
    $metadata = [ordered]@{}

    $metadata['WrongCnameTarget'] = [pscustomobject]@{
        Severity = 'medium'
        Title    = 'CNAME points to wrong host'
        Summary  = { param($c) "Autodiscover for $($c.Domain) points to $($c.TargetDisplay), so Outlook won't reach the right Exchange endpoint." }
        Determination = { param($c) "Topology $($c.Topology); autodiscover.$($c.Domain) resolves to $($c.TargetDisplay) instead of autodiscover.outlook.com." }
        Fix      = { param($c) "Update autodiscover.$($c.Domain) CNAME to autodiscover.outlook.com so Exchange Online profiles configure automatically." }
    }

    $metadata['ExoCnameMissingObserved'] = [pscustomobject]@{
        Severity = 'info'
        Title    = 'Autodiscover CNAME missing (unconfirmed)'
        Summary  = { param($c) "Outlook couldn't resolve autodiscover.$($c.Domain) during this run, so Exchange Online profile setup may fail if the issue persists." }
        Determination = { param($c) "Topology $($c.Topology); single-run NXDOMAIN for autodiscover.$($c.Domain) and HTTPS probe failed." }
        Fix      = { param($c) "Verify autodiscover.$($c.Domain) CNAME points to autodiscover.outlook.com and confirm the record has replicated." }
    }

    $metadata['ExoCnameMissingConfirmed'] = [pscustomobject]@{
        Severity = 'medium'
        Title    = 'Autodiscover CNAME missing (confirmed)'
        Summary  = { param($c) "Outlook still can't resolve autodiscover.$($c.Domain), so Exchange Online mailboxes fail to auto-configure." }
        Determination = { param($c) "Topology $($c.Topology); repeated NXDOMAIN for autodiscover.$($c.Domain) and HTTPS probe failed." }
        Fix      = { param($c) "Publish autodiscover.$($c.Domain) CNAME to autodiscover.outlook.com or repair the DNS zone delegation." }
    }

    $metadata['MissingOnPremEndpoint'] = [pscustomobject]@{
        Severity = 'high'
        Title    = 'No Autodiscover endpoint published'
        Summary  = { param($c) "Outlook can't reach on-prem Exchange for $($c.Domain) because no Autodiscover A or SRV records are published." }
        Determination = { param($c) "Topology $($c.Topology); Autodiscover A/AAAA and SRV records missing." }
        Fix      = { param($c) "Publish autodiscover.$($c.Domain) A/AAAA or _autodiscover._tcp SRV records that point to your Exchange Client Access endpoint with valid TLS." }
    }

    $metadata['SrvWrongPort'] = [pscustomobject]@{
        Severity = 'medium'
        Title    = 'SRV record misconfigured'
        Summary  = { param($c) "Autodiscover SRV for $($c.Domain) uses port $($c.Port) instead of 443, so clients will fail the initial HTTPS bootstrap." }
        Determination = { param($c) "Topology $($c.Topology); SRV record uses port $($c.Port) for Autodiscover." }
        Fix      = { param($c) "Update _autodiscover._tcp.$($c.Domain) SRV to priority 0 weight 0 port 443 targeting your Autodiscover host." }
    }

    $metadata['MissingRecords'] = [pscustomobject]@{
        Severity = 'high'
        Title    = 'Autodiscover lookups failed'
        Summary  = { param($c) "Clients can't locate Exchange services for $($c.Domain) because all Autodiscover DNS lookups failed." }
        Determination = { param($c) "Topology $($c.Topology); Autodiscover CNAME/A/SRV lookups returned no usable records." }
        Fix      = { param($c) "Publish Autodiscover records for $($c.Domain) so Outlook can bootstrap automatically." }
    }

    $metadata['ScpMisleadsToOnPrem'] = [pscustomobject]@{
        Severity = 'high'
        Title    = 'SCP points to legacy endpoint'
        Summary  = { param($c) "Domain-joined Outlook will follow an Autodiscover SCP to $($c.TargetDisplay), which no longer hosts $($c.Domain) mailboxes, so new profiles break." }
        Determination = { param($c) "JoinState $($c.JoinState); SCP targets $($c.TargetDisplay) while topology is $($c.Topology)." }
        Fix      = { param($c) "Remove or update the Autodiscover SCP in Active Directory to direct clients to Exchange Online (autodiscover-s.outlook.com)." }
    }

    $metadata['ScpMismatchOnPrem'] = [pscustomobject]@{
        Severity = 'medium'
        Title    = 'SCP mismatches on-prem endpoint'
        Summary  = { param($c) "Autodiscover SCP points to $($c.TargetDisplay), which doesn't match the published on-prem endpoints for $($c.Domain), so domain-joined Outlook may fail before falling back." }
        Determination = { param($c) "JoinState $($c.JoinState); SCP host $($c.TargetDisplay) differs from Autodiscover DNS targets." }
        Fix      = { param($c) "Update the Autodiscover SCP so it matches the published on-prem Autodiscover endpoint for $($c.Domain)." }
    }

    return $metadata
}

function Get-AutodiscoverDnsEvidence {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)]$LookupMap,
        [psobject]$HttpProbe
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $cnameTargets = @()
    $cnameError = $null

    if ($LookupMap.ContainsKey('Autodiscover')) {
        $cname = $LookupMap['Autodiscover']
        if ($cname.Success -eq $true -and $cname.Targets -and $cname.Targets.Count -gt 0) {
            $cnameTargets = @($cname.Targets | Where-Object { $_ })
            $lines.Add("autodiscover.$Domain CNAME → $([string]::Join(', ', $cnameTargets)) (OK)") | Out-Null
        } elseif ($cname.Success -eq $false -and $cname.Error) {
            $cnameError = [string]$cname.Error
            $lines.Add("autodiscover.$Domain CNAME lookup failed: $cnameError") | Out-Null
        } else {
            $lines.Add("autodiscover.$Domain CNAME lookup returned no targets.") | Out-Null
        }
    }

    $addressList = New-Object System.Collections.Generic.List[string]
    foreach ($label in @('AutodiscoverA','AutodiscoverAAAA')) {
        if (-not $LookupMap.ContainsKey($label)) { continue }
        $record = $LookupMap[$label]
        $type = if ($record.Type) { [string]$record.Type } else { $label }
        if ($record.Success -eq $true -and $record.Addresses -and $record.Addresses.Count -gt 0) {
            $addresses = @($record.Addresses | Where-Object { $_ })
            foreach ($addr in $addresses) { $addressList.Add([string]$addr) | Out-Null }
            $lines.Add("autodiscover.$Domain $type → $([string]::Join(', ', $addresses)) (OK)") | Out-Null
        } elseif ($record.Success -eq $false -and $record.Error) {
            $lines.Add("autodiscover.$Domain $type lookup failed: $($record.Error)") | Out-Null
        }
    }

    $srvLines = New-Object System.Collections.Generic.List[string]
    $srvError = $null
    if ($LookupMap.ContainsKey('AutodiscoverSrv')) {
        $srv = $LookupMap['AutodiscoverSrv']
        if ($srv.Success -eq $true -and $srv.Records) {
            foreach ($record in (ConvertTo-AutodiscoverArray -Value $srv.Records)) {
                if (-not $record) { continue }
                $target = if ($record.Target) { [string]$record.Target } else { '(no target)' }
                $priority = if ($record.PSObject.Properties['Priority']) { $record.Priority } else { $null }
                $weight = if ($record.PSObject.Properties['Weight']) { $record.Weight } else { $null }
                $port = if ($record.PSObject.Properties['Port']) { $record.Port } else { $null }
                $status = if ($port -eq 443) { 'OK' } else { "Port $port" }
                $display = "$priority $weight $port $target ($status)"
                $srvLines.Add($display) | Out-Null
                $lines.Add("_autodiscover._tcp.$Domain SRV → $display") | Out-Null
            }
        } elseif ($srv.Success -eq $false -and $srv.Error) {
            $srvError = [string]$srv.Error
            $lines.Add("_autodiscover._tcp.$Domain SRV lookup failed: $srvError") | Out-Null
        }
    }

    $mxLines = New-Object System.Collections.Generic.List[string]
    $mx = if ($LookupMap.ContainsKey('Mx')) { $LookupMap['Mx'] } else { $null }
    if ($mx) {
        if ($mx.Success -eq $true -and $mx.Records) {
            foreach ($record in (ConvertTo-AutodiscoverArray -Value $mx.Records)) {
                if (-not $record) { continue }
                $preference = if ($record.PSObject.Properties['Preference']) { $record.Preference } else { 0 }
                $target = if ($record.PSObject.Properties['Target']) { [string]$record.Target } else { '(no target)' }
                $display = "$preference $target"
                $mxLines.Add($display) | Out-Null
                $lines.Add("$Domain MX → $display") | Out-Null
            }
        } elseif ($mx.Success -eq $false -and $mx.Error) {
            $lines.Add("$Domain MX lookup failed: $($mx.Error)") | Out-Null
        }
    }

    $httpStatus = $null
    if ($HttpProbe) {
        if ($HttpProbe.Success) {
            $statusCode = if ($HttpProbe.StatusCode) { "HTTP $($HttpProbe.StatusCode)" } else { 'HTTP success' }
            if ($HttpProbe.Location) {
                $statusCode = "$statusCode → $($HttpProbe.Location)"
            }
            $httpStatus = "$statusCode (OK)"
        } elseif ($HttpProbe.StatusCode) {
            $httpStatus = "HTTP $($HttpProbe.StatusCode)"
            if ($HttpProbe.Error) {
                $httpStatus = "$httpStatus: $($HttpProbe.Error)"
            }
        } elseif ($HttpProbe.Error) {
            $httpStatus = [string]$HttpProbe.Error
        }

        if ($httpStatus) {
            $lines.Add("autodiscover.$Domain HTTP probe → $httpStatus") | Out-Null
        }
    }

    return [pscustomobject]@{
        Lines        = $lines.ToArray()
        CnameTargets = $cnameTargets
        CnameError   = $cnameError
        AAddresses   = $addressList.ToArray()
        SrvRecords   = $srvLines.ToArray()
        SrvError     = $srvError
        MxRecords    = $mxLines.ToArray()
        HttpStatus   = $httpStatus
    }
}

function Get-AutodiscoverScpEvidence {
    param(
        [object[]]$Entries,
        [string[]]$ProblemHosts,
        [string]$JoinState
    )

    if ($JoinState -notin @('AD-joined', 'HAADJ')) { return @() }
    if (-not $Entries -or $Entries.Count -eq 0) { return @() }

    $lines = New-Object System.Collections.Generic.List[string]
    $problemSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($host in (ConvertTo-AutodiscoverArray -Value $ProblemHosts)) {
        if ($host) { $problemSet.Add($host) | Out-Null }
    }

    foreach ($entry in $Entries) {
        if (-not $entry) { continue }
        $host = if ($entry.Host) { $entry.Host } else { '(unknown host)' }
        $status = if ($problemSet.Contains($host)) { 'Mismatch' } else { 'OK' }
        $url = if ($entry.Url) { $entry.Url } else { '(no URL provided)' }
        $lines.Add("SCP ServiceBinding: $url (Host $host, $status)") | Out-Null
    }

    return $lines.ToArray()
}

function Evaluate-AutodiscoverDomain {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)]$DomainEntry,
        [Parameter(Mandatory)]$TopologyInfo,
        [Parameter(Mandatory)]$JoinInfo,
        [Parameter()]$ScpData,
        [string]$CollectedAtUtc
    )

    $lookupMap = $TopologyInfo.LookupMap
    $issues = New-Object System.Collections.Generic.List[pscustomobject]
    $metadata = Get-AutodiscoverIssueMetadata

    $topology = $TopologyInfo.Topology
    $joinState = $JoinInfo.JoinState
    $isDomainScoped = ($joinState -eq 'AD-joined' -or $joinState -eq 'HAADJ')
    $isWorkgroupLike = ($joinState -eq 'Workgroup' -or $joinState -eq 'AADJ')

    $httpProbe = $null
    if ($DomainEntry.PSObject.Properties['HttpProbe'] -and $DomainEntry.HttpProbe) {
        $httpProbe = $DomainEntry.HttpProbe
    }
    $httpSuccess = ($httpProbe -and $httpProbe.Success -eq $true)

    $cnameEntry = if ($lookupMap.ContainsKey('Autodiscover')) { $lookupMap['Autodiscover'] } else { $null }
    $cnameNxDomain = Test-AutodiscoverCnameNxDomain -Lookup $cnameEntry
    $nxState = Update-AutodiscoverNxDomainHistory -Domain $Domain -IsNxDomain $cnameNxDomain
    $consecutiveNxDomain = $nxState.Consecutive

    if ($topology -eq 'EXO' -or $topology -eq 'Hybrid') {
        if ($TopologyInfo.HasMsCname) {
            # Healthy configuration
        } elseif ($TopologyInfo.HasCname) {
            $issues.Add([pscustomobject]@{
                Reason        = 'WrongCnameTarget'
                TargetDisplay = ($TopologyInfo.CnameTargets -join ', ')
            }) | Out-Null
        } elseif (-not $httpSuccess) {
            $reason = if ($consecutiveNxDomain -and -not $isWorkgroupLike) { 'ExoCnameMissingConfirmed' } else { 'ExoCnameMissingObserved' }
            $issues.Add([pscustomobject]@{ Reason = $reason }) | Out-Null
        }
    } elseif ($topology -eq 'On-prem') {
        $hasValidEndpoint = $TopologyInfo.HasARecord -or ($TopologyInfo.HasSrv -and $TopologyInfo.HasSrv443) -or ($TopologyInfo.HasCname -and -not $TopologyInfo.HasMsCname)
        if (-not $hasValidEndpoint) {
            $issues.Add([pscustomobject]@{ Reason = 'MissingOnPremEndpoint' }) | Out-Null
        } elseif ($TopologyInfo.HasSrv -and -not $TopologyInfo.HasSrv443) {
            $badPorts = New-Object System.Collections.Generic.List[int]
            $srv = if ($lookupMap.ContainsKey('AutodiscoverSrv')) { $lookupMap['AutodiscoverSrv'] } else { $null }
            if ($srv) {
                foreach ($record in (ConvertTo-AutodiscoverArray -Value $srv.Records)) {
                    if ($record -and $record.PSObject.Properties['Port'] -and $record.Port -ne 443) {
                        $badPorts.Add([int]$record.Port) | Out-Null
                    }
                }
            }
            if ($badPorts.Count -gt 0) {
                $issues.Add([pscustomobject]@{
                    Reason = 'SrvWrongPort'
                    Port   = ($badPorts | Select-Object -First 1)
                }) | Out-Null
            }
        }
    }

    if (-not $TopologyInfo.HasCname -and -not $TopologyInfo.HasARecord -and (-not $TopologyInfo.HasSrv -or $TopologyInfo.SrvTargets.Count -eq 0)) {
        if (-not $httpSuccess) {
            $issues.Add([pscustomobject]@{ Reason = 'MissingRecords' }) | Out-Null
        }
    }

    $scpEntries = @()
    $scpProblems = @()
    if ($ScpData -and $ScpData.Entries) {
        $matches = @()
        if ($ScpData.Entries.ContainsKey($Domain)) { $matches = $ScpData.Entries[$Domain] }
        elseif ($ScpData.Entries.ContainsKey('*')) { $matches = $ScpData.Entries['*'] }
        $scpEntries = @($matches | Where-Object { $_ })
    }

    if ($isDomainScoped -and $scpEntries.Count -gt 0) {
        $hosts = $scpEntries | ForEach-Object { $_.Host } | Where-Object { $_ }
        if ($topology -eq 'EXO' -or $topology -eq 'Hybrid') {
            $invalid = @($hosts | Where-Object { $_ -notmatch '(?i)autodiscover(-s)?\.outlook\.com$' })
            if ($invalid.Count -gt 0) {
                $issues.Add([pscustomobject]@{
                    Reason        = 'ScpMisleadsToOnPrem'
                    TargetDisplay = ($invalid -join ', ')
                    ProblemHosts  = $invalid
                }) | Out-Null
                $scpProblems = $invalid
            }
        } elseif ($topology -eq 'On-prem') {
            $validHosts = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            $validHosts.Add("autodiscover.$Domain") | Out-Null
            foreach ($target in $TopologyInfo.SrvTargets) { if ($target) { $validHosts.Add($target) | Out-Null } }
            if ($TopologyInfo.HasCname -and -not $TopologyInfo.HasMsCname) {
                foreach ($target in $TopologyInfo.CnameTargets) { if ($target) { $validHosts.Add($target.ToLowerInvariant()) | Out-Null } }
            }

            $mismatch = @()
            foreach ($host in $hosts) {
                if (-not $host) { continue }
                if (-not $validHosts.Contains($host)) {
                    $mismatch += $host
                }
            }

            if ($mismatch.Count -gt 0) {
                $issues.Add([pscustomobject]@{
                    Reason        = 'ScpMismatchOnPrem'
                    TargetDisplay = ($mismatch -join ', ')
                    ProblemHosts  = $mismatch
                }) | Out-Null
                $scpProblems = $mismatch
            }
        }
    }

    $issueMetadata = $metadata
    $selected = $null
    $selectedMeta = $null
    foreach ($issue in $issues) {
        if (-not $issueMetadata.ContainsKey($issue.Reason)) { continue }
        $candidateMeta = $issueMetadata[$issue.Reason]
        if (-not $selectedMeta) {
            $selected = $issue
            $selectedMeta = $candidateMeta
            continue
        }

        $currentSeverity = $selectedMeta.Severity
        $candidateSeverity = $candidateMeta.Severity
        $currentRank = switch ($currentSeverity) { 'high' { 3 } 'medium' { 2 } 'low' { 1 } 'info' { 0 } default { 0 } }
        $candidateRank = switch ($candidateSeverity) { 'high' { 3 } 'medium' { 2 } 'low' { 1 } 'info' { 0 } default { 0 } }
        if ($candidateRank -gt $currentRank) {
            $selected = $issue
            $selectedMeta = $candidateMeta
        }
    }

    $dnsEvidence = Get-AutodiscoverDnsEvidence -Domain $Domain -LookupMap $lookupMap -HttpProbe $httpProbe
    $scpEvidence = Get-AutodiscoverScpEvidence -Entries $scpEntries -ProblemHosts $scpProblems -JoinState $joinState

    $baseData = [ordered]@{
        Domain                = $Domain
        Topology              = $topology
        JoinState             = $joinState
        IssuesDetected        = @($issues | ForEach-Object { $_.Reason })
        CnameTargets          = $TopologyInfo.CnameTargets
        HasMsCname            = $TopologyInfo.HasMsCname
        CnameNxDomain         = $cnameNxDomain
        ConsecutiveNxDomain   = $consecutiveNxDomain
        SrvTargets            = $TopologyInfo.SrvTargets
        ARecordAddresses      = $TopologyInfo.ARecordAddresses
        MxTargets             = $TopologyInfo.MxTargets
        HttpProbeStatus       = $dnsEvidence.HttpStatus
    }

    if (-not $selectedMeta) {
        $summary = "Autodiscover for $Domain is published correctly, so Outlook can auto-configure mailboxes."
        $evidence = [ordered]@{
            Summary       = $summary
            Domain        = $Domain
            Topology      = $topology
            JoinState     = $joinState
            DNS           = $dnsEvidence.Lines
        }
        if ($CollectedAtUtc) { $evidence['CollectedAtUtc'] = $CollectedAtUtc }
        if ($dnsEvidence.CnameTargets.Count -gt 0) { $evidence['CNAME Targets'] = $dnsEvidence.CnameTargets }
        if ($dnsEvidence.AAddresses.Count -gt 0) { $evidence['A/AAAA Addresses'] = $dnsEvidence.AAddresses }
        if ($dnsEvidence.SrvRecords.Count -gt 0) { $evidence['SRV Records'] = $dnsEvidence.SrvRecords }
        if ($dnsEvidence.MxRecords.Count -gt 0) { $evidence['MX Records'] = $dnsEvidence.MxRecords }
        if ($dnsEvidence.HttpStatus) { $evidence['HTTP Probe Status'] = $dnsEvidence.HttpStatus }
        if ($scpEvidence.Count -gt 0) { $evidence['SCP'] = $scpEvidence }
        $evidence['Determination'] = "Topology $topology with healthy Autodiscover records."
        $evidence['Fix'] = 'No action required.'

        return [pscustomobject]@{
            Outcome   = 'Normal'
            Title     = "Office/Autodiscover DNS: $Domain Autodiscover published correctly → Info"
            Evidence  = $evidence
            Data      = $baseData
        }
    }

    $context = [ordered]@{
        Domain        = $Domain
        Topology      = $topology
        JoinState     = $joinState
        TargetDisplay = $selected.TargetDisplay
        Port          = $selected.Port
    }

    $summaryText = & $selectedMeta.Summary $context
    $determinationText = & $selectedMeta.Determination $context
    $fixText = & $selectedMeta.Fix $context

    $evidence = [ordered]@{
        Summary       = $summaryText
        Domain        = $Domain
        Topology      = $topology
        JoinState     = $joinState
        DNS           = $dnsEvidence.Lines
    }
    if ($CollectedAtUtc) { $evidence['CollectedAtUtc'] = $CollectedAtUtc }
    if ($dnsEvidence.CnameTargets.Count -gt 0) { $evidence['CNAME Targets'] = $dnsEvidence.CnameTargets }
    if ($dnsEvidence.CnameError) { $evidence['CNAME Error'] = $dnsEvidence.CnameError }
    if ($dnsEvidence.AAddresses.Count -gt 0) { $evidence['A/AAAA Addresses'] = $dnsEvidence.AAddresses }
    if ($dnsEvidence.SrvRecords.Count -gt 0) { $evidence['SRV Records'] = $dnsEvidence.SrvRecords }
    elseif ($dnsEvidence.SrvError) { $evidence['SRV Error'] = $dnsEvidence.SrvError }
    if ($dnsEvidence.MxRecords.Count -gt 0) { $evidence['MX Records'] = $dnsEvidence.MxRecords }
    if ($dnsEvidence.HttpStatus) { $evidence['HTTP Probe Status'] = $dnsEvidence.HttpStatus }
    if ($scpEvidence.Count -gt 0) { $evidence['SCP'] = $scpEvidence }
    if ($ScpData -and $ScpData.Errors -and $ScpData.Errors.Count -gt 0) {
        $evidence['SCP Lookup Notes'] = $ScpData.Errors
    }
    $evidence['Determination'] = $determinationText
    $evidence['Fix'] = $fixText

    $titleSuffix = $selectedMeta.Title
    $titleSeverity = ($selectedMeta.Severity.Substring(0,1).ToUpper() + $selectedMeta.Severity.Substring(1))
    $title = "Office/Autodiscover DNS: $Domain ($topology) $titleSuffix → $titleSeverity"

    return [pscustomobject]@{
        Outcome  = 'Issue'
        Severity = $selectedMeta.Severity
        Title    = $title
        Evidence = $evidence
        Data     = $baseData
        Summary  = $summaryText
    }
}

function Invoke-AutodiscoverDnsHeuristic {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    $autodiscoverArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autodiscover-dns'
    Write-HeuristicDebug -Source 'Office' -Message 'Resolved autodiscover-dns artifact' -Data ([ordered]@{
        Found = [bool]$autodiscoverArtifact
    })

    if (-not $autodiscoverArtifact) {
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autodiscoverArtifact)
    Write-HeuristicDebug -Source 'Office' -Message 'Evaluating autodiscover DNS payload' -Data ([ordered]@{
        HasResults = [bool]($payload -and $payload.Results)
    })

    if (-not ($payload -and $payload.Results)) {
        return
    }

    $joinInfo = Get-AutodiscoverJoinContext -Context $Context
    $scpData = Get-AutodiscoverScpData -Context $Context
    $collectedAtUtc = $null
    if ($payload.PSObject.Properties['CollectedAtUtc'] -and $payload.CollectedAtUtc) {
        $collectedAtUtc = [string]$payload.CollectedAtUtc
    }

    foreach ($domainEntry in (ConvertTo-AutodiscoverArray -Value $payload.Results)) {
        if (-not $domainEntry) { continue }
        $domain = $domainEntry.Domain
        if ([string]::IsNullOrWhiteSpace($domain)) { continue }

        $lookupMap = ConvertTo-AutodiscoverLookupMap -Lookups $domainEntry.Lookups
        $topologyInfo = Get-AutodiscoverTopologyInfo -Domain $domain -LookupMap $lookupMap

        $finding = Evaluate-AutodiscoverDomain -Domain $domain -DomainEntry $domainEntry -TopologyInfo $topologyInfo -JoinInfo $joinInfo -ScpData $scpData -CollectedAtUtc $collectedAtUtc

        if ($finding.Outcome -eq 'Issue') {
            Add-CategoryIssue -CategoryResult $Result -Severity $finding.Severity -Title $finding.Title -Evidence $finding.Evidence -Subcategory 'Autodiscover DNS' -Data $finding.Data -Explanation $finding.Summary
        } elseif ($finding.Outcome -eq 'Normal') {
            Add-CategoryNormal -CategoryResult $Result -Title $finding.Title -Evidence $finding.Evidence -Subcategory 'Autodiscover DNS'
        }
    }
}
