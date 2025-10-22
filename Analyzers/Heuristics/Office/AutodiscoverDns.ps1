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
        Topology           = 'Unknown'
        HasCname           = $false
        HasMsCname         = $false
        CnameTargets       = @()
        HasSrv             = $false
        HasSrv443          = $false
        SrvTargets         = @()
        HasARecord         = $false
        ARecordAddresses   = @()
        HasMsMx            = $false
        LookupMap          = $LookupMap
    }

    $domainLower = $Domain.ToLowerInvariant()

    $cname = if ($LookupMap.ContainsKey('Autodiscover')) { $LookupMap['Autodiscover'] } else { $null }
    if ($cname -and $cname.Success -eq $true) {
        $targets = @($cname.Targets | Where-Object { $_ })
        $result.CnameTargets = $targets
        if ($targets.Count -gt 0) { $result.HasCname = $true }
        if ($targets | Where-Object { $_ -match '(?i)autodiscover\.outlook\.com$' }) { $result.HasMsCname = $true }
    }

    $srv = if ($LookupMap.ContainsKey('AutodiscoverSrv')) { $LookupMap['AutodiscoverSrv'] } else { $null }
    if ($srv -and $srv.Success -eq $true) {
        $result.HasSrv = $true
        $targets = New-Object System.Collections.Generic.List[string]
        foreach ($record in (ConvertTo-AutodiscoverArray -Value $srv.Records)) {
            if (-not $record) { continue }
            $target = $null
            if ($record.PSObject.Properties['Target'] -and $record.Target) {
                $target = $record.Target.ToLowerInvariant()
                $targets.Add($target) | Out-Null
            }
            if ($record.PSObject.Properties['Port'] -and $record.Port -eq 443) {
                $result.HasSrv443 = $true
            }
        }
        $result.SrvTargets = $targets.ToArray()
    }

    $aRecords = New-Object System.Collections.Generic.List[string]
    foreach ($label in @('AutodiscoverA','AutodiscoverAAAA')) {
        if (-not $LookupMap.ContainsKey($label)) { continue }
        $record = $LookupMap[$label]
        if ($record -and $record.Success -eq $true) {
            foreach ($address in (ConvertTo-AutodiscoverArray -Value $record.Addresses)) {
                if (-not $address) { continue }
                $aRecords.Add([string]$address) | Out-Null
            }
        }
    }
    if ($aRecords.Count -gt 0) {
        $result.HasARecord = $true
        $result.ARecordAddresses = $aRecords.ToArray()
    }

    $mx = if ($LookupMap.ContainsKey('Mx')) { $LookupMap['Mx'] } else { $null }
    if ($mx -and $mx.Success -eq $true) {
        foreach ($target in (ConvertTo-AutodiscoverArray -Value $mx.Targets)) {
            if (-not $target) { continue }
            $text = [string]$target
            if ($text -match '(?i)(?:^|\.)protection\.outlook\.com$' -or $text -match '(?i)outlook\.com$') {
                $result.HasMsMx = $true
                break
            }
        }
    }

    $onPremSignal = $false
    if ($result.HasARecord) { $onPremSignal = $true }
    if ($result.HasSrv -and $result.SrvTargets.Count -gt 0) { $onPremSignal = $true }
    if ($result.HasCname -and -not $result.HasMsCname) { $onPremSignal = $true }

    if ($result.HasMsCname -and $onPremSignal) {
        $result.Topology = 'Hybrid'
    } elseif ($result.HasMsCname -or $result.HasMsMx) {
        $result.Topology = 'EXO'
    } elseif ($onPremSignal) {
        $result.Topology = 'On-prem'
    }

    return [pscustomobject]$result
}

function Get-AutodiscoverIssueMetadata {
    $metadata = [ordered]@{}

    $metadata['MissingCname'] = [pscustomobject]@{
        Severity = 'high'
        Title    = 'CNAME missing'
        Summary  = { param($c) "Outlook can't auto-configure $($c.Domain) mailboxes because autodiscover.$($c.Domain) is missing the CNAME to autodiscover.outlook.com." }
        Determination = { param($c) "Topology $($c.Topology); autodiscover.$($c.Domain) CNAME missing." }
        Fix      = { param($c) "Add or repair autodiscover.$($c.Domain) CNAME to autodiscover.outlook.com." }
    }

    $metadata['WrongCnameTarget'] = [pscustomobject]@{
        Severity = 'medium'
        Title    = 'CNAME points to wrong host'
        Summary  = { param($c) "Autodiscover for $($c.Domain) points to $($c.TargetDisplay), so Outlook may fail to connect cloud mailboxes." }
        Determination = { param($c) "Topology $($c.Topology); autodiscover.$($c.Domain) resolves to $($c.TargetDisplay) instead of autodiscover.outlook.com." }
        Fix      = { param($c) "Update autodiscover.$($c.Domain) CNAME to autodiscover.outlook.com for Exchange Online mailboxes." }
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
        [Parameter(Mandatory)]$LookupMap
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $cname = if ($LookupMap.ContainsKey('Autodiscover')) { $LookupMap['Autodiscover'] } else { $null }
    if ($cname) {
        if ($cname.Success -eq $true -and $cname.Targets -and $cname.Targets.Count -gt 0) {
            $lines.Add(("autodiscover.{0} CNAME → {1} (OK)" -f $Domain, ($cname.Targets -join ', '))) | Out-Null
        } elseif ($cname.Success -eq $false) {
            $lines.Add(("autodiscover.{0} CNAME lookup failed: {1}" -f $Domain, $cname.Error)) | Out-Null
        } else {
            $lines.Add(("autodiscover.{0} CNAME lookup returned no targets." -f $Domain)) | Out-Null
        }
    }

    foreach ($label in @('AutodiscoverA','AutodiscoverAAAA')) {
        if (-not $LookupMap.ContainsKey($label)) { continue }
        $record = $LookupMap[$label]
        $type = $record.Type
        if ($record.Success -eq $true -and $record.Addresses -and $record.Addresses.Count -gt 0) {
            $lines.Add(("autodiscover.{0} {1} → {2} (OK)" -f $Domain, $type, ($record.Addresses -join ', '))) | Out-Null
        } elseif ($record.Success -eq $false) {
            $lines.Add(("autodiscover.{0} {1} lookup failed: {2}" -f $Domain, $type, $record.Error)) | Out-Null
        }
    }

    if ($LookupMap.ContainsKey('AutodiscoverSrv')) {
        $srv = $LookupMap['AutodiscoverSrv']
        if ($srv.Success -eq $true -and $srv.Records) {
            foreach ($record in (ConvertTo-AutodiscoverArray -Value $srv.Records)) {
                if (-not $record) { continue }
                $target = $record.Target
                $port = $record.Port
                $priority = $record.Priority
                $weight = $record.Weight
                $status = if ($port -eq 443) { 'OK' } else { "Port $port" }
                $lines.Add(("_autodiscover._tcp.{0} SRV → {1} {2} {3} {4} ({5})" -f $Domain, $priority, $weight, $port, $target, $status)) | Out-Null
            }
        } elseif ($srv.Success -eq $false) {
            $lines.Add(("_autodiscover._tcp.{0} SRV lookup failed: {1}" -f $Domain, $srv.Error)) | Out-Null
        }
    }

    if ($LookupMap.ContainsKey('Mx')) {
        $mx = $LookupMap['Mx']
        if ($mx.Success -eq $true -and $mx.Records) {
            foreach ($record in (ConvertTo-AutodiscoverArray -Value $mx.Records)) {
                if (-not $record) { continue }
                $lines.Add(("{0} MX → {1} {2}" -f $Domain, $record.Preference, $record.Target)) | Out-Null
            }
        }
    }

    return $lines.ToArray()
}

function Get-AutodiscoverScpEvidence {
    param(
        [object[]]$Entries,
        [string[]]$ProblemHosts
    )

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
        $lines.Add(("SCP ServiceBinding: {0} (Host {1}, {2})" -f $url, $host, $status)) | Out-Null
    }

    return $lines.ToArray()
}

function Evaluate-AutodiscoverDomain {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)]$DomainEntry,
        [Parameter(Mandatory)]$TopologyInfo,
        [Parameter(Mandatory)]$JoinInfo,
        [Parameter()]$ScpData
    )

    $lookupMap = $TopologyInfo.LookupMap
    $issues = New-Object System.Collections.Generic.List[pscustomobject]
    $metadata = Get-AutodiscoverIssueMetadata

    $topology = $TopologyInfo.Topology

    if ($topology -eq 'EXO' -or $topology -eq 'Hybrid') {
        if ($TopologyInfo.HasMsCname) {
            # Healthy for this axis
        } elseif ($TopologyInfo.HasCname) {
            $issues.Add([pscustomobject]@{
                Reason        = 'WrongCnameTarget'
                TargetDisplay = ($TopologyInfo.CnameTargets -join ', ')
            }) | Out-Null
        } else {
            $issues.Add([pscustomobject]@{ Reason = 'MissingCname' }) | Out-Null
        }
    } elseif ($topology -eq 'On-prem') {
        $hasValidEndpoint = $TopologyInfo.HasARecord -or ($TopologyInfo.HasSrv -and $TopologyInfo.HasSrv443) -or ($TopologyInfo.HasCname -and -not $TopologyInfo.HasMsCname)
        if (-not $hasValidEndpoint) {
            $issues.Add([pscustomobject]@{ Reason = 'MissingOnPremEndpoint' }) | Out-Null
        } elseif ($TopologyInfo.HasSrv -and -not $TopologyInfo.HasSrv443) {
            $badPorts = New-Object System.Collections.Generic.List[int]
            $srv = $lookupMap['AutodiscoverSrv']
            foreach ($record in (ConvertTo-AutodiscoverArray -Value $srv.Records)) {
                if ($record -and $record.PSObject.Properties['Port'] -and $record.Port -ne 443) {
                    $badPorts.Add([int]$record.Port) | Out-Null
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
        $issues.Add([pscustomobject]@{ Reason = 'MissingRecords' }) | Out-Null
    }

    $scpEntries = @()
    $scpProblems = @()
    if ($ScpData -and $ScpData.Entries) {
        $matches = @()
        if ($ScpData.Entries.ContainsKey($Domain)) { $matches = $ScpData.Entries[$Domain] }
        elseif ($ScpData.Entries.ContainsKey('*')) { $matches = $ScpData.Entries['*'] }
        $scpEntries = @($matches | Where-Object { $_ })
    }

    $joinState = $JoinInfo.JoinState
    $isDomainScoped = ($joinState -eq 'AD-joined' -or $joinState -eq 'HAADJ')

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
        $currentRank = switch ($currentSeverity) { 'high' { 3 } 'medium' { 2 } 'low' { 1 } default { 0 } }
        $candidateRank = switch ($candidateSeverity) { 'high' { 3 } 'medium' { 2 } 'low' { 1 } default { 0 } }
        if ($candidateRank -gt $currentRank) {
            $selected = $issue
            $selectedMeta = $candidateMeta
        }
    }

    $dnsEvidence = Get-AutodiscoverDnsEvidence -Domain $Domain -LookupMap $lookupMap
    $scpEvidence = Get-AutodiscoverScpEvidence -Entries $scpEntries -ProblemHosts $scpProblems

    $issueReasons = New-Object System.Collections.Generic.List[string]
    foreach ($issue in $issues) {
        if (-not $issue) { continue }
        if ($issue.PSObject.Properties['Reason'] -and $issue.Reason) {
            $issueReasons.Add([string]$issue.Reason) | Out-Null
        }
    }
    $issueReasonArray = $issueReasons.ToArray()
    $issueReasonText = if ($issueReasonArray.Count -gt 0) { $issueReasonArray -join ', ' } else { 'None' }

    $cnameTargetsList = New-Object System.Collections.Generic.List[string]
    foreach ($target in (ConvertTo-AutodiscoverArray -Value $TopologyInfo.CnameTargets)) {
        if (-not $target) { continue }
        $cnameTargetsList.Add([string]$target) | Out-Null
    }
    $cnameTargets = $cnameTargetsList.ToArray()
    $cnameTargetsText = if ($cnameTargets.Count -gt 0) { $cnameTargets -join ', ' } else { '(none)' }

    $srvTargetsList = New-Object System.Collections.Generic.List[string]
    foreach ($target in (ConvertTo-AutodiscoverArray -Value $TopologyInfo.SrvTargets)) {
        if (-not $target) { continue }
        $srvTargetsList.Add([string]$target) | Out-Null
    }
    $srvTargets = $srvTargetsList.ToArray()
    $srvTargetsText = if ($srvTargets.Count -gt 0) { $srvTargets -join ', ' } else { '(none)' }

    $aRecordList = New-Object System.Collections.Generic.List[string]
    foreach ($address in (ConvertTo-AutodiscoverArray -Value $TopologyInfo.ARecordAddresses)) {
        if (-not $address) { continue }
        $aRecordList.Add([string]$address) | Out-Null
    }
    $aRecordAddresses = $aRecordList.ToArray()
    $aRecordAddressesText = if ($aRecordAddresses.Count -gt 0) { $aRecordAddresses -join ', ' } else { '(none)' }

    $contextLines = New-Object System.Collections.Generic.List[string]
    $contextLines.Add("Topology: $topology") | Out-Null
    $contextLines.Add("Join state: $joinState") | Out-Null
    $contextLines.Add("Issues detected: $issueReasonText") | Out-Null
    $contextLines.Add("CNAME targets: $cnameTargetsText") | Out-Null
    $contextLines.Add("SRV targets: $srvTargetsText") | Out-Null
    $contextLines.Add("A/AAAA addresses: $aRecordAddressesText") | Out-Null
    $contextArray = $contextLines.ToArray()

    $signalsDetail = [ordered]@{
        IssuesDetected    = $issueReasonArray
        CnameTargets      = $cnameTargets
        SrvTargets        = $srvTargets
        ARecordAddresses  = $aRecordAddresses
    }

    if (-not $selectedMeta) {
        $summary = "Autodiscover for $Domain is published correctly, so Outlook can auto-configure mailboxes."
        if ($contextArray.Count -gt 0) {
            $contextSummaryLines = $contextArray | ForEach-Object { "- $_" }
            $contextSummaryText = $contextSummaryLines -join "`n"
            $summary = "$summary`n`nContext:`n$contextSummaryText"
        }

        $evidence = [ordered]@{
            Summary       = $summary
            Domain        = $Domain
            Topology      = $topology
            JoinState     = $joinState
            DNS           = $dnsEvidence
        }
        if ($scpEvidence.Count -gt 0) { $evidence['SCP'] = $scpEvidence }
        if ($contextArray.Count -gt 0) { $evidence['Context'] = $contextArray }
        $evidence['Signals'] = $signalsDetail
        $evidence['Determination'] = "Topology $topology with healthy Autodiscover records."
        $evidence['Fix'] = 'No action required.'

        return [pscustomobject]@{
            Outcome   = 'Normal'
            Title     = "Office/Autodiscover DNS: $Domain Autodiscover published correctly → Info"
            Evidence  = $evidence
            Summary   = $summary
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
    if ($contextArray.Count -gt 0) {
        $contextSummaryLines = $contextArray | ForEach-Object { "- $_" }
        $contextSummaryText = $contextSummaryLines -join "`n"
        $summaryText = "$summaryText`n`nContext:`n$contextSummaryText"
    }
    $determinationText = & $selectedMeta.Determination $context
    $fixText = & $selectedMeta.Fix $context

    $evidence = [ordered]@{
        Summary       = $summaryText
        Domain        = $Domain
        Topology      = $topology
        JoinState     = $joinState
        DNS           = $dnsEvidence
    }
    if ($scpEvidence.Count -gt 0) { $evidence['SCP'] = $scpEvidence }
    if ($contextArray.Count -gt 0) { $evidence['Context'] = $contextArray }
    if ($ScpData -and $ScpData.Errors -and $ScpData.Errors.Count -gt 0) {
        $evidence['SCP Lookup Notes'] = $ScpData.Errors
    }
    $evidence['Signals'] = $signalsDetail
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

    foreach ($domainEntry in (ConvertTo-AutodiscoverArray -Value $payload.Results)) {
        if (-not $domainEntry) { continue }
        $domain = $domainEntry.Domain
        if ([string]::IsNullOrWhiteSpace($domain)) { continue }

        $lookupMap = ConvertTo-AutodiscoverLookupMap -Lookups $domainEntry.Lookups
        $topologyInfo = Get-AutodiscoverTopologyInfo -Domain $domain -LookupMap $lookupMap

        $finding = Evaluate-AutodiscoverDomain -Domain $domain -DomainEntry $domainEntry -TopologyInfo $topologyInfo -JoinInfo $joinInfo -ScpData $scpData

        if ($finding.Outcome -eq 'Issue') {
            Add-CategoryIssue -CategoryResult $Result -Severity $finding.Severity -Title $finding.Title -Evidence $finding.Evidence -Subcategory 'Autodiscover DNS' -Explanation $finding.Summary
        } elseif ($finding.Outcome -eq 'Normal') {
            Add-CategoryNormal -CategoryResult $Result -Title $finding.Title -Evidence $finding.Evidence -Subcategory 'Autodiscover DNS'
        }
    }
}
