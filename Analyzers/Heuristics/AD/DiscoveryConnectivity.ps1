# Structured remediation mapping:
# - Headings become text steps with titles for quick scanning.
# - Symptom and triage guidance translate to text or note steps in the order presented.
# - PowerShell blocks remain code steps, keeping commands and placeholders.
# - Follow-up paragraphs (SYSVOL access, firewall reminder) become note steps.
$script:AdDiscoveryConnectivityRemediation = @'
[
  {
    "type": "text",
    "title": "Active Directory Health",
    "content": "DNS Discovery / Discovery / Connectivity / SYSVOL"
  },
  {
    "type": "text",
    "title": "Symptoms",
    "content": "SRV records not resolvable; no DC candidates; can't reach DC ports; SYSVOL/NETLOGON unreachable."
  },
  {
    "type": "text",
    "title": "Triage",
    "content": "Verify domain suffix and DNS before deeper troubleshooting."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "$domain = (Get-CimInstance Win32_ComputerSystem).Domain\nResolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.$domain\nResolve-DnsName $domain\nTest-NetConnection -ComputerName (Get-ADDomainController -Discover -ErrorAction SilentlyContinue).HostName -Port 389,445,88,135,3268"
  },
  {
    "type": "note",
    "content": "Check secure channel and time as a follow-up step if the discovery tests succeed."
  },
  {
    "type": "text",
    "title": "Fix",
    "content": "Point client DNS to AD DCs only (no public resolvers on domain members)."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "Get-DnsClientServerAddress -AddressFamily IPv4 |\n  Where-Object { $_.ServerAddresses -notcontains '10.x.x.x' } |\n  ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses @('10.x.x.x','10.y.y.y') }"
  },
  {
    "type": "text",
    "title": "Restore SYSVOL access",
    "content": "\\\\<domain>\\SYSVOL should open; if not, check DFS Namespace/DFS Replication service state on DCs and validate site connectivity."
  },
  {
    "type": "note",
    "content": "Ensure branch firewalls allow Kerberos/LDAP/SMB to domain controllers."
  },
  {
    "type": "text",
    "title": "Validate",
    "content": "Confirm discovery succeeds and SYSVOL is reachable."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "nltest /dsgetdc:<yourdomain>\nTest-Path \\\\$env:USERDNSDOMAIN\\SYSVOL"
  }
]
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
        $srvErrorText = ($srvErrors | ForEach-Object {
                if ($_.Error) { "{0}: {1}" -f $_.Query, $_.Error } else { "{0}: no records" -f $_.Query }
            }) -join '; '
        $evidenceLines = @()
        if (-not [string]::IsNullOrWhiteSpace($srvErrorText)) { $evidenceLines += $srvErrorText }

        $hostEvidence = $candidateHosts | Sort-Object -Unique
        if ($hostEvidence -and $hostEvidence.Count -gt 0) {
            $evidenceLines += ("Candidate hosts: {0}" -f ($hostEvidence -join ', '))
        }

        $addressValues = @()
        foreach ($addressEntry in $candidateAddresses) {
            if (-not $addressEntry) { continue }
            if ($addressEntry -is [System.Collections.IEnumerable] -and -not ($addressEntry -is [string])) {
                foreach ($nested in $addressEntry) {
                    if ($nested) { $addressValues += [string]$nested }
                }
            } else {
                $addressValues += [string]$addressEntry
            }
        }
        $addressEvidence = $addressValues | Sort-Object -Unique
        if ($addressEvidence -and $addressEvidence.Count -gt 0) {
            $evidenceLines += ("Candidate addresses: {0}" -f ($addressEvidence -join ', '))
        }

        $srvLookupSnapshots = @()
        foreach ($entry in $srvLookups) {
            if (-not $entry) { continue }
            try {
                $srvLookupSnapshots += ($entry | ConvertTo-Json -Depth 6 -Compress)
            } catch {
                $srvLookupSnapshots += ($entry | Out-String).Trim()
            }
        }
        if ($srvLookupSnapshots.Count -gt 0) {
            $evidenceLines += 'SRV lookup snapshots:'
            $evidenceLines += $srvLookupSnapshots
        }

        if ($evidenceLines.Count -eq 0) { $evidenceLines = $null }

        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'AD SRV records not resolvable, so Active Directory is unreachable.' -Evidence $evidenceLines -Subcategory 'DNS Discovery' -Area 'AD/DiscoveryConnectivity' -Explanation 'Discovery context: SRV lookup failures prevented locating domain controllers. Candidate host/address details and raw lookup snapshots are attached.' -Remediation $script:AdDiscoveryConnectivityRemediation
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
        $evidenceLines = @()
        if ($candidates -and $candidates.Count -gt 0) {
            $evidenceLines += ("Candidate hosts discovered: {0}" -f (($candidates | Sort-Object -Unique) -join ', '))
        }

        if ($candidateHosts -and $candidateHosts.Count -gt 0) {
            $evidenceLines += ("Candidate hostnames (raw): {0}" -f (($candidateHosts | Sort-Object -Unique) -join ', '))
        }

        $candidateAddressLines = @()
        foreach ($addressEntry in $candidateAddresses) {
            if (-not $addressEntry) { continue }
            if ($addressEntry -is [System.Collections.IEnumerable] -and -not ($addressEntry -is [string])) {
                foreach ($nested in $addressEntry) {
                    if ($nested) { $candidateAddressLines += [string]$nested }
                }
            } else {
                $candidateAddressLines += [string]$addressEntry
            }
        }
        if ($candidateAddressLines.Count -gt 0) {
            $evidenceLines += ("Candidate addresses: {0}" -f (($candidateAddressLines | Sort-Object -Unique) -join ', '))
        }

        if (-not [string]::IsNullOrWhiteSpace($evidenceText)) { $evidenceLines += $evidenceText }

        if ($Discovery.DsGetDc) {
            try {
                $evidenceLines += ('dsgetdc snapshot: ' + ($Discovery.DsGetDc | ConvertTo-Json -Depth 6 -Compress))
            } catch {
                $evidenceLines += ('dsgetdc snapshot: ' + (($Discovery.DsGetDc | Out-String).Trim()))
            }
        }

        if ($Discovery.DcList) {
            try {
                $evidenceLines += ('dclist snapshot: ' + ($Discovery.DcList | ConvertTo-Json -Depth 6 -Compress))
            } catch {
                $evidenceLines += ('dclist snapshot: ' + (($Discovery.DcList | Out-String).Trim()))
            }
        }

        if ($evidenceLines.Count -eq 0) { $evidenceLines = $null }

        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'No reachable DC candidates were discovered.' -Evidence $evidenceLines -Subcategory 'Discovery' -Area 'AD/DiscoveryConnectivity' -Explanation 'Discovery context: NLTEST/DC locator calls returned no reachable domain controllers. Candidate discovery snapshots are attached.' -Remediation $script:AdDiscoveryConnectivityRemediation
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

    $portSummaries = @()
    foreach ($host in ($portMap.Keys | Sort-Object)) {
        $ports = $portMap[$host]
        if (-not $ports) { continue }
        $portStates = @()
        foreach ($port in ($ports.Keys | Sort-Object)) {
            $state = if ($ports[$port]) { 'open' } else { 'blocked' }
            $portStates += ("{0}={1}" -f $port, $state)
        }
        if ($portStates.Count -gt 0) {
            $portSummaries += ("{0}: {1}" -f $host, ($portStates -join ', '))
        }
    }

    $shareSummaries = @()
    foreach ($shareEntry in ($shareMap.Keys | Sort-Object)) {
        $shares = $shareMap[$shareEntry]
        if (-not $shares) { continue }
        $shareStates = @()
        foreach ($shareName in ($shares.Keys | Sort-Object)) {
            $state = if ($shares[$shareName]) { 'accessible' } else { 'blocked' }
            $shareStates += ("{0}={1}" -f $shareName, $state)
        }
        if ($shareStates.Count -gt 0) {
            $shareSummaries += ("{0}: {1}" -f $shareEntry, ($shareStates -join ', '))
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
        $evidenceLines = @()
        $candidateSummary = $Candidates | Sort-Object -Unique
        if ($candidateSummary -and $candidateSummary.Count -gt 0) {
            $evidenceLines += ("Candidates tested: {0}" -f ($candidateSummary -join ', '))
        }

        if ($portSummaries.Count -gt 0) {
            $evidenceLines += 'Port test results by host:'
            $evidenceLines += $portSummaries
        }

        if ($reachableWithShares.Count -gt 0) {
            $evidenceLines += ("Hosts with port + share access: {0}" -f (($reachableWithShares | Sort-Object -Unique) -join ', '))
        } else {
            $evidenceLines += 'Hosts with port + share access: none'
        }

        if ($sharesFailingHosts.Count -gt 0) {
            $evidenceLines += ("Hosts failing SYSVOL/NETLOGON after port success: {0}" -f (($sharesFailingHosts | Sort-Object -Unique) -join ', '))
        }

        $evidenceLines += ("Tests without errors: {0}" -f $testsWithoutErrors)
        $evidenceLines += ("All required ports tested: {0}" -f $allPortsTested)

        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Cannot reach any DC on required ports, so Active Directory is unreachable.' -Evidence $evidenceLines -Subcategory 'Connectivity' -Area 'AD/DiscoveryConnectivity' -Explanation 'Connectivity context: all port probes against candidate domain controllers failed for required LDAP/Kerberos/SMB endpoints. Port maps and share follow-ups are summarized.' -Remediation $script:AdDiscoveryConnectivityRemediation
    }

    if ($sharesFailingHosts.Count -gt 0) {
        $sharesEvidenceLines = @()
        $sharesEvidenceLines += ("Hosts failing SYSVOL/NETLOGON: {0}" -f (($sharesFailingHosts | Sort-Object -Unique) -join ', '))

        if ($reachableWithShares.Count -gt 0) {
            $sharesEvidenceLines += ("Hosts with successful share access: {0}" -f (($reachableWithShares | Sort-Object -Unique) -join ', '))
        } else {
            $sharesEvidenceLines += 'Hosts with successful share access: none'
        }

        if ($fullyReachableHosts.Count -gt 0) {
            $sharesEvidenceLines += ("Hosts with required ports open: {0}" -f (($fullyReachableHosts | Sort-Object -Unique) -join ', '))
        } else {
            $sharesEvidenceLines += 'Hosts with required ports open: none'
        }

        if ($shareSummaries.Count -gt 0) {
            $sharesEvidenceLines += 'Share test results by host:'
            $sharesEvidenceLines += $shareSummaries
        }

        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title "Domain shares unreachable (DFS/DNS/auth), so SYSVOL/NETLOGON can't deliver GPOs." -Evidence $sharesEvidenceLines -Subcategory 'SYSVOL' -Area 'AD/DiscoveryConnectivity' -Explanation 'Connectivity context: SYSVOL/NETLOGON share checks failed even when required ports were reachable. Share probes by host are summarized.' -Remediation $script:AdDiscoveryConnectivityRemediation
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
