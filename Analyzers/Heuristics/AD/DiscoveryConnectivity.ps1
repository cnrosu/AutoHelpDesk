$script:AdDiscoveryConnectivityRemediation = @'
Active Directory Health
DNS Discovery / Discovery / Connectivity / SYSVOL

Symptoms (cards): SRV records not resolvable; no DC candidates; can't reach DC ports; SYSVOL/NETLOGON unreachable.
Triage

Verify domain suffix & DNS:

```powershell
$domain = (Get-CimInstance Win32_ComputerSystem).Domain
Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.$domain
Resolve-DnsName $domain
Test-NetConnection -ComputerName (Get-ADDomainController -Discover -ErrorAction SilentlyContinue).HostName -Port 389,445,88,135,3268
```

Check secure channel & time (see below).
Fix

Point client DNS to AD DCs only (no public resolvers on domain members):

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4 |
  Where-Object { $_.ServerAddresses -notcontains '10.x.x.x' } |
  ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses @('10.x.x.x','10.y.y.y') }
```

Restore SYSVOL access:
\\<domain>\SYSVOL should open; if not, check DFS Namespace/DFS Replication service state on DCs and site connectivity.

Firewall in path: ensure branch firewalls allow Kerberos/LDAP/SMB to DCs.
Validate

```powershell
nltest /dsgetdc:<yourdomain>
Test-Path \$env:USERDNSDOMAIN\SYSVOL
```
'@

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

    $candidates = @()
    $candidateHosts = @()
    $candidateAddresses = @()
    if ($Discovery -and $Discovery.Candidates) {
        foreach ($candidate in $Discovery.Candidates) {
            if ($candidate -and $candidate.Hostname) {
                $candidateHosts += $candidate.Hostname
                $candidates += $candidate.Hostname.ToLowerInvariant()
            }
            if ($candidate -and $candidate.Addresses) { $candidateAddresses += $candidate.Addresses }
        }
    }
    $candidates = $candidates | Sort-Object -Unique

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
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'AD SRV records not resolvable, so Active Directory is unreachable.' -Evidence $evidence -Subcategory 'DNS Discovery' -Remediation $script:AdDiscoveryConnectivityRemediation -Data @{
            Area = 'AD/DiscoveryConnectivity'
            Kind = 'SrvLookup'
            Discovery = @{
                SrvLookups         = $Discovery.SrvLookups
                SrvSuccess         = $srvSuccess
                CandidateHosts     = $candidateHosts
                CandidateAddresses = $candidateAddresses
            }
        }
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
        $nltestEvidence = if ($candidates -and $candidates.Count -gt 0) { $candidates -join ', ' } else { $evidenceText }
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'No reachable DC candidates were discovered.' -Evidence $nltestEvidence -Subcategory 'Discovery' -Remediation $script:AdDiscoveryConnectivityRemediation -Data @{
            Area = 'AD/DiscoveryConnectivity'
            Kind = 'NltestDiscovery'
            Discovery = @{
                NltestSuccess     = $nltestSuccess
                Candidates        = $candidates
                CandidateHosts    = $candidateHosts
                CandidateAddresses = $candidateAddresses
            }
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

    $sharesFailingHosts = @()
    foreach ($host in $fullyReachableHosts) {
        if (-not $shareMap.ContainsKey($host)) { continue }
        $shares = $shareMap[$host].Values
        if (-not ($shares -contains $true)) {
            $sharesFailingHosts += $host
        }
    }

    $testsWithoutErrors = 0
    if ($reachTests) {
        foreach ($test in $reachTests) {
            if ($test -and -not $test.Error) { $testsWithoutErrors++ }
        }
    }

    $allPortsTested = $portMap.Count -gt 0
    if ($Candidates.Count -gt 0 -and $allPortsTested -and $fullyReachableHosts.Count -eq 0 -and $testsWithoutErrors -gt 0) {
        $evidenceText = ($portMap.Keys | Sort-Object) -join ', '
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Cannot reach any DC on required ports, so Active Directory is unreachable.' -Evidence $evidenceText -Subcategory 'Connectivity' -Remediation $script:AdDiscoveryConnectivityRemediation -Data @{
            Area = 'AD/DiscoveryConnectivity'
            Kind = 'PortReachability'
            Connectivity = @{
                PortMap             = $portMap
                FullyReachableHosts = $fullyReachableHosts
                ReachableWithShares = $reachableWithShares
                SharesFailingHosts  = $sharesFailingHosts
                TestsWithoutErrors  = $testsWithoutErrors
                AllPortsTested      = $allPortsTested
                Candidates          = $candidates
            }
        }
    }

    if ($sharesFailingHosts.Count -gt 0) {
        $sharesEvidence = ($sharesFailingHosts | Sort-Object -Unique) -join ', '
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title "Domain shares unreachable (DFS/DNS/auth), so SYSVOL/NETLOGON can't deliver GPOs." -Evidence $sharesEvidence -Subcategory 'SYSVOL' -Remediation $script:AdDiscoveryConnectivityRemediation -Data @{
            Area = 'AD/DiscoveryConnectivity'
            Kind = 'SysvolNetlogon'
            Sysvol = @{
                SharesFailingHosts  = $sharesFailingHosts
                ReachableWithShares = $reachableWithShares
                FullyReachableHosts = $fullyReachableHosts
            }
        }
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
