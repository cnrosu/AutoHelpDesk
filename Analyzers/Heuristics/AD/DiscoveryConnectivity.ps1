function Add-AdDiscoveryFindings {
    param(
        [Parameter(Mandatory)]
        $Result,
        $Discovery
    )

    $srvLookups = @()
    $srvSuccess = $false
    if ($Discovery -and $Discovery.SrvLookups) {
        foreach ($prop in $Discovery.SrvLookups.PSObject.Properties) {
            $entry = $prop.Value
            if ($entry) {
                $srvLookups += $entry
                if ($entry.Succeeded -eq $true -and $entry.Records -and $entry.Records.Count -gt 0) {
                    $srvSuccess = $true
                }
            }
        }
    }

    $nltestSuccess = $false
    if ($Discovery) {
        if ($Discovery.DsGetDc -and $Discovery.DsGetDc.Succeeded) { $nltestSuccess = $true }
        if ($Discovery.DcList -and $Discovery.DcList.Succeeded) { $nltestSuccess = $true }
    }

    if ($srvSuccess) {
        $dcNames = @()
        if ($Discovery -and $Discovery.Candidates) {
            foreach ($candidate in $Discovery.Candidates) {
                if ($candidate.Hostname) { $dcNames += $candidate.Hostname }
            }
        }
        $dcEvidence = if ($dcNames) { ($dcNames | Sort-Object -Unique) -join ', ' } else { 'SRV queries resolved.' }
        Add-CategoryNormal -CategoryResult $Result -Title 'GOOD AD/DNS (SRV resolves)' -Evidence $dcEvidence -Subcategory 'DNS Discovery'
    } else {
        $srvErrors = $srvLookups | Where-Object { $_ -and $_.Succeeded -ne $true }
        $evidence = ($srvErrors | ForEach-Object {
                if ($_.Error) { "{0}: {1}" -f $_.Query, $_.Error } else { "{0}: no records" -f $_.Query }
            }) -join '; '
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'AD SRV records not resolvable, so Active Directory is unreachable.' -Evidence $evidence -Subcategory 'DNS Discovery'
    }

    if (-not $srvSuccess -and -not $nltestSuccess -and $Discovery) {
        $evidenceBuilder = [System.Text.StringBuilder]::new()
        if ($Discovery.DsGetDc) {
            if ($Discovery.DsGetDc.Error) { Add-StringFragment -Builder $evidenceBuilder -Fragment ("dsgetdc: {0}" -f $Discovery.DsGetDc.Error) }
            elseif ($Discovery.DsGetDc.Output) { Add-StringFragment -Builder $evidenceBuilder -Fragment ("dsgetdc output: {0}" -f ($Discovery.DsGetDc.Output -join ' | ')) }
        }
        if ($Discovery.DcList) {
            if ($Discovery.DcList.Error) { Add-StringFragment -Builder $evidenceBuilder -Fragment ("dclist: {0}" -f $Discovery.DcList.Error) }
            elseif ($Discovery.DcList.Output) { Add-StringFragment -Builder $evidenceBuilder -Fragment ("dclist output: {0}" -f ($Discovery.DcList.Output -join ' | ')) }
        }
        $evidenceText = $evidenceBuilder.ToString()
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'No DC discovered, so Active Directory is unreachable.' -Evidence $evidenceText -Subcategory 'Discovery'
    }

    $candidates = @()
    if ($Discovery -and $Discovery.Candidates) {
        foreach ($candidate in $Discovery.Candidates) {
            if ($candidate.Hostname) { $candidates += $candidate.Hostname.ToLowerInvariant() }
        }
    }
    $candidates = $candidates | Sort-Object -Unique

    $candidateHosts = @()
    $candidateAddresses = @()
    if ($Discovery -and $Discovery.Candidates) {
        foreach ($candidate in $Discovery.Candidates) {
            if ($candidate -and $candidate.Hostname) { $candidateHosts += $candidate.Hostname }
            if ($candidate -and $candidate.Addresses) { $candidateAddresses += $candidate.Addresses }
        }
    }

    [pscustomobject]@{
        SrvSuccess         = $srvSuccess
        NltestSuccess      = $nltestSuccess
        Candidates         = $candidates
        CandidateHosts     = $candidateHosts
        CandidateAddresses = $candidateAddresses
    }
}

function Add-AdConnectivityFindings {
    param(
        [Parameter(Mandatory)]
        $Result,
        $Reachability,
        $Sysvol,
        [string[]]$Candidates
    )

    $portMap = @{}
    $reachTests = if ($Reachability) { $Reachability.Tests } else { $null }
    if ($reachTests) {
        foreach ($test in $reachTests) {
            if (-not $test) { continue }
            $target = if ($test.PSObject.Properties['Target']) { $test.Target } else { $null }
            if (-not $target) { continue }
            $key = $target.ToLowerInvariant()
            if (-not $portMap.ContainsKey($key)) { $portMap[$key] = @{} }
            if ($test.PSObject.Properties['Port']) {
                $portMap[$key][$test.Port] = [bool]$test.Success
            }
        }
    }

    $requiredPorts = @(88, 389, 445, 135)
    $fullyReachableHosts = @()
    foreach ($entry in $portMap.GetEnumerator()) {
        $host = $entry.Key
        $ports = $entry.Value
        $allOpen = $true
        foreach ($port in $requiredPorts) {
            if (-not ($ports.ContainsKey($port) -and $ports[$port])) {
                $allOpen = $false
                break
            }
        }
        if ($allOpen) { $fullyReachableHosts += $host }
    }

    $shareMap = @{}
    $shareTests = if ($Sysvol) { $Sysvol.Tests } else { $null }
    if ($shareTests) {
        foreach ($test in $shareTests) {
            if (-not $test) { continue }
            $target = if ($test.PSObject.Properties['Target']) { $test.Target } else { $null }
            $share = if ($test.PSObject.Properties['Share']) { $test.Share } else { $null }
            if (-not $target -or -not $share) { continue }
            $key = $target.ToLowerInvariant()
            if (-not $shareMap.ContainsKey($key)) { $shareMap[$key] = @{} }
            $shareMap[$key][$share.ToUpperInvariant()] = [bool]$test.Success
        }
    }

    $reachableWithShares = @()
    foreach ($host in $fullyReachableHosts) {
        if ($shareMap.ContainsKey($host)) {
            $values = $shareMap[$host].Values
            if ($values -and ($values -contains $true)) {
                $reachableWithShares += $host
            }
        }
    }

    if ($reachableWithShares.Count -gt 0) {
        Add-CategoryNormal -CategoryResult $Result -Title 'GOOD AD/Reachability (≥1 DC reachable + SYSVOL)' -Evidence (($reachableWithShares | Sort-Object -Unique) -join ', ') -Subcategory 'Connectivity'
    }

    $testsWithoutErrors = 0
    if ($reachTests) {
        foreach ($test in $reachTests) {
            if ($test -and -not $test.Error) { $testsWithoutErrors++ }
        }
    }

    $allPortsTested = $portMap.Count -gt 0
    if ($Candidates.Count -gt 0 -and $allPortsTested -and $fullyReachableHosts.Count -eq 0 -and $testsWithoutErrors -gt 0) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Cannot reach any DC on required ports, so Active Directory is unreachable.' -Evidence (($portMap.Keys | Sort-Object) -join ', ') -Subcategory 'Connectivity'
    }

    $sharesFailingHosts = @()
    foreach ($host in $fullyReachableHosts) {
        if (-not $shareMap.ContainsKey($host)) { continue }
        $shares = $shareMap[$host].Values
        if (-not ($shares -contains $true)) {
            $sharesFailingHosts += $host
        }
    }

    if ($sharesFailingHosts.Count -gt 0) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title "Domain shares unreachable (DFS/DNS/auth), so SYSVOL/NETLOGON can't deliver GPOs." -Evidence (($sharesFailingHosts | Sort-Object -Unique) -join ', ') -Subcategory 'SYSVOL'
    }

    [pscustomobject]@{
        FullyReachableHosts = $fullyReachableHosts
        ReachableWithShares = $reachableWithShares
        SharesFailingHosts  = $sharesFailingHosts
        PortMap             = $portMap
        TestsWithoutErrors  = $testsWithoutErrors
        AllPortsTested      = $allPortsTested
    }
}
