<#!
.SYNOPSIS
    Active Directory health heuristics focused on discovery, reachability, secure channel, time, Kerberos, and GPO posture.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Get-FirstPayloadProperty {
    param(
        $Payload,
        [string]$Name
    )

    if (-not $Payload) { return $null }
    if ($Payload.PSObject.Properties[$Name]) { return $Payload.$Name }
    return $null
}

function Get-ArtifactPayloadValue {
    param(
        $Artifact,
        [string]$Property
    )

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $Artifact)
    if (-not $payload) { return $null }
    if ($Property) { return Get-FirstPayloadProperty -Payload $payload -Name $Property }
    return $payload
}

function Add-StringFragment {
    param(
        [Parameter(Mandatory)]
        [System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory)]
        [string]$Fragment,
        [string]$Separator = '; '
    )

    if ([string]::IsNullOrWhiteSpace($Fragment)) { return }
    if ($Builder.Length -gt 0 -and $Separator) {
        $null = $Builder.Append($Separator)
    }
    $null = $Builder.Append($Fragment)
}

function Get-CleanTimePeerName {
    param(
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $clean = $Value.Trim()
    $clean = $clean -replace ',0x[0-9a-fA-F]+', ''
    $clean = $clean.Trim()

    if ($clean -match '^(?<host>[^\s\(]+)\s*\(') {
        $clean = $matches['host']
    }

    return $clean.TrimEnd('.')
}

function Test-IsDomainTimePeer {
    param(
        [string]$Peer,
        [string[]]$CandidateHosts,
        [string[]]$CandidateAddresses,
        [string]$DomainName
    )

    if ([string]::IsNullOrWhiteSpace($Peer)) { return $false }

    $peerLower = $Peer.ToLowerInvariant().TrimEnd('.')

    if ($DomainName) {
        $domainLower = $DomainName.ToLowerInvariant().TrimStart('.').TrimEnd('.')
        if ($peerLower -eq $domainLower) { return $true }
        if ($peerLower.EndsWith(".$domainLower")) { return $true }
    }

    if ($CandidateHosts) {
        foreach ($host in $CandidateHosts) {
            if ([string]::IsNullOrWhiteSpace($host)) { continue }
            $hostLower = $host.ToLowerInvariant().TrimEnd('.')
            if ($peerLower -eq $hostLower) { return $true }
            $short = ($hostLower -split '\.')[0]
            if ($short -and $peerLower -eq $short) { return $true }
        }
    }

    if ($CandidateAddresses) {
        foreach ($address in $CandidateAddresses) {
            if ([string]::IsNullOrWhiteSpace($address)) { continue }
            if ($peerLower -eq $address.ToLowerInvariant()) { return $true }
        }
    }

    return $false
}

function Invoke-ADHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'AD' -Message 'Starting Active Directory heuristics evaluation' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Active Directory Health'

    $adArtifact = Get-AnalyzerArtifact -Context $Context -Name 'ad-health'
    Write-HeuristicDebug -Source 'AD' -Message 'Resolved ad-health artifact' -Data ([ordered]@{
        Found = [bool]$adArtifact
    })
    $adPayload = Get-ArtifactPayloadValue -Artifact $adArtifact -Property $null

    $domainStatus = $null
    if ($adPayload) {
        $domainStatus = Get-FirstPayloadProperty -Payload $adPayload -Name 'DomainStatus'
    }

    if (-not $domainStatus) {
        Write-HeuristicDebug -Source 'AD' -Message 'Falling back to system artifact for domain status'
        $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
        if ($systemArtifact) {
            $systemPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
            if ($systemPayload -and $systemPayload.ComputerSystem -and -not $systemPayload.ComputerSystem.Error) {
                $domainStatus = [pscustomobject]@{
                    DomainJoined = $systemPayload.ComputerSystem.PartOfDomain
                    Domain       = $systemPayload.ComputerSystem.Domain
                    Forest       = $null
                    DomainRole   = if ($systemPayload.ComputerSystem.PSObject.Properties['DomainRole']) { $systemPayload.ComputerSystem.DomainRole } else { $null }
                }
            }
        }
    }

    if (-not $domainStatus) {
        Write-HeuristicDebug -Source 'AD' -Message 'Domain status unavailable; reporting collection issue'
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'AD health data unavailable, so Active Directory reachability is unknown.' -Subcategory 'Collection'
        return $result
    }

    $domainJoined = $false
    if ($domainStatus.PSObject.Properties['DomainJoined']) {
        $domainJoined = [bool]$domainStatus.DomainJoined
    }

    if (-not $domainJoined) {
        Write-HeuristicDebug -Source 'AD' -Message 'System not domain joined; marking AD as not applicable'
        Add-CategoryNormal -CategoryResult $result -Title 'AD not applicable' -Subcategory 'Discovery'
        return $result
    }

    $domainName = if ($domainStatus.PSObject.Properties['Domain']) { $domainStatus.Domain } else { $null }
    $domainRole = $null
    $domainRoleInt = $null
    if ($domainStatus.PSObject.Properties['DomainRole']) {
        $domainRole = $domainStatus.DomainRole
        try { $domainRoleInt = [int]$domainRole } catch { $domainRoleInt = $null }
    }

    if ($domainName) {
        Add-CategoryNormal -CategoryResult $result -Title ("Domain joined: {0}" -f $domainName) -Subcategory 'Discovery'
    }

    $discovery = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Discovery' } else { $null }
    $reachability = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Reachability' } else { $null }
    $sysvol = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Sysvol' } else { $null }
    $timeInfo = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Time' } else { $null }
    $kerberosInfo = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Kerberos' } else { $null }
    $secureInfo = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Secure' } else { $null }
    $gpoInfo = if ($adPayload) { Get-FirstPayloadProperty -Payload $adPayload -Name 'Gpo' } else { $null }

    $srvLookups = @()
    $srvSuccess = $false
    if ($discovery -and $discovery.SrvLookups) {
        foreach ($prop in $discovery.SrvLookups.PSObject.Properties) {
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
    if ($discovery) {
        if ($discovery.DsGetDc -and $discovery.DsGetDc.Succeeded) { $nltestSuccess = $true }
        if ($discovery.DcList -and $discovery.DcList.Succeeded) { $nltestSuccess = $true }
    }

    if ($srvSuccess) {
        $dcNames = @()
        if ($discovery -and $discovery.Candidates) {
            foreach ($candidate in $discovery.Candidates) {
                if ($candidate.Hostname) { $dcNames += $candidate.Hostname }
            }
        }
        $dcEvidence = if ($dcNames) { ($dcNames | Sort-Object -Unique) -join ', ' } else { 'SRV queries resolved.' }
        Add-CategoryNormal -CategoryResult $result -Title 'GOOD AD/DNS (SRV resolves)' -Evidence $dcEvidence -Subcategory 'DNS Discovery'
    } else {
        $srvErrors = $srvLookups | Where-Object { $_ -and $_.Succeeded -ne $true }
        $evidence = ($srvErrors | ForEach-Object {
                if ($_.Error) { "{0}: {1}" -f $_.Query, $_.Error } else { "{0}: no records" -f $_.Query }
            }) -join '; '
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'AD SRV records not resolvable, so Active Directory is unreachable.' -Evidence $evidence -Subcategory 'DNS Discovery'
    }

    if (-not $srvSuccess -and -not $nltestSuccess -and $discovery) {
        $evidenceBuilder = [System.Text.StringBuilder]::new()
        if ($discovery.DsGetDc) {
            if ($discovery.DsGetDc.Error) { Add-StringFragment -Builder $evidenceBuilder -Fragment ("dsgetdc: {0}" -f $discovery.DsGetDc.Error) }
            elseif ($discovery.DsGetDc.Output) { Add-StringFragment -Builder $evidenceBuilder -Fragment ("dsgetdc output: {0}" -f ($discovery.DsGetDc.Output -join ' | ')) }
        }
        if ($discovery.DcList) {
            if ($discovery.DcList.Error) { Add-StringFragment -Builder $evidenceBuilder -Fragment ("dclist: {0}" -f $discovery.DcList.Error) }
            elseif ($discovery.DcList.Output) { Add-StringFragment -Builder $evidenceBuilder -Fragment ("dclist output: {0}" -f ($discovery.DcList.Output -join ' | ')) }
        }
        $evidenceText = $evidenceBuilder.ToString()
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No DC discovered, so Active Directory is unreachable.' -Evidence $evidenceText -Subcategory 'Discovery'
    }

    $candidates = @()
    if ($discovery -and $discovery.Candidates) {
        foreach ($candidate in $discovery.Candidates) {
            if ($candidate.Hostname) { $candidates += $candidate.Hostname.ToLowerInvariant() }
        }
    }
    $candidates = $candidates | Sort-Object -Unique

    $portMap = @{}
    $reachTests = if ($reachability) { $reachability.Tests } else { $null }
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
    $shareTests = if ($sysvol) { $sysvol.Tests } else { $null }
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
        Add-CategoryNormal -CategoryResult $result -Title 'GOOD AD/Reachability (≥1 DC reachable + SYSVOL)' -Evidence (($reachableWithShares | Sort-Object -Unique) -join ', ') -Subcategory 'Connectivity'
    }

    $testsWithoutErrors = 0
    if ($reachTests) {
        foreach ($test in $reachTests) {
            if ($test -and -not $test.Error) { $testsWithoutErrors++ }
        }
    }

    $allPortsTested = $portMap.Count -gt 0
    if ($candidates.Count -gt 0 -and $allPortsTested -and $fullyReachableHosts.Count -eq 0 -and $testsWithoutErrors -gt 0) {
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Cannot reach any DC on required ports, so Active Directory is unreachable.' -Evidence (($portMap.Keys | Sort-Object) -join ', ') -Subcategory 'Connectivity'
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
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title "Domain shares unreachable (DFS/DNS/auth), so SYSVOL/NETLOGON can't deliver GPOs." -Evidence (($sharesFailingHosts | Sort-Object -Unique) -join ', ') -Subcategory 'SYSVOL'
    }

    $candidateHosts = @()
    $candidateAddresses = @()
    if ($discovery -and $discovery.Candidates) {
        foreach ($candidate in $discovery.Candidates) {
            if ($candidate -and $candidate.Hostname) { $candidateHosts += $candidate.Hostname }
            if ($candidate -and $candidate.Addresses) { $candidateAddresses += $candidate.Addresses }
        }
    }

    $timeSkewHigh = $false
    if ($timeInfo) {
        $parsed = $timeInfo.Parsed
        $offset = $null
        if ($parsed -and $parsed.PSObject.Properties['OffsetSeconds']) {
            $offset = $parsed.OffsetSeconds
        }
        $synchronized = $null
        if ($parsed -and $parsed.PSObject.Properties['Synchronized']) {
            $synchronized = $parsed.Synchronized
        }

        if ($offset -ne $null -and [math]::Abs([double]$offset) -gt 300) {
            $timeSkewHigh = $true
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Kerberos time skew, breaking Active Directory authentication.' -Evidence ("Offset {0} seconds" -f [math]::Round([double]$offset, 2)) -Subcategory 'Time Synchronization'
        } elseif ($synchronized -eq $false -or ($timeInfo.Status -and $timeInfo.Status.Succeeded -ne $true)) {
            $timeSkewHigh = $true
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Kerberos time skew, breaking Active Directory authentication.' -Evidence 'Time service not synchronized.' -Subcategory 'Time Synchronization'
        } elseif ($offset -ne $null -and [math]::Abs([double]$offset) -le 300) {
            Add-CategoryNormal -CategoryResult $result -Title 'GOOD Time (skew ≤5m)' -Evidence ("Offset {0} seconds" -f [math]::Round([double]$offset, 2)) -Subcategory 'Time Synchronization'
        }

        $clientType = $null
        $clientServersRaw = $null
        $peerEntries = @()
        $sourceRaw = $null
        if ($parsed) {
            if ($parsed.PSObject.Properties['ClientType']) { $clientType = $parsed.ClientType }
            if ($parsed.PSObject.Properties['ClientNtpServer']) { $clientServersRaw = $parsed.ClientNtpServer }
            if ($parsed.PSObject.Properties['PeerEntries'] -and $parsed.PeerEntries) { $peerEntries = $parsed.PeerEntries }
            if ($parsed.PSObject.Properties['Source']) { $sourceRaw = $parsed.Source }
        }

        $manualPeers = @()
        if ($clientServersRaw) {
            $components = $clientServersRaw -split '\s+'
            foreach ($component in $components) {
                $cleanPeer = Get-CleanTimePeerName -Value $component
                if (-not $cleanPeer) { continue }
                if ($cleanPeer -eq '(Local)') { continue }
                $manualPeers += $cleanPeer
            }
        }

        $peerNames = @()
        foreach ($peerEntry in $peerEntries) {
            $cleanPeer = Get-CleanTimePeerName -Value $peerEntry
            if ($cleanPeer) { $peerNames += $cleanPeer }
        }

        $sourceName = if ($sourceRaw) { Get-CleanTimePeerName -Value $sourceRaw } else { $null }

        $combinedPeers = @()
        if ($manualPeers) { $combinedPeers += $manualPeers }
        if ($peerNames) { $combinedPeers += $peerNames }
        $combinedPeers = $combinedPeers | Sort-Object -Unique

        $suspiciousPeers = @()
        foreach ($peer in $combinedPeers) {
            if (-not $peer) { continue }
            $peerLower = $peer.ToLowerInvariant()
            if ($peerLower -match 'local cmos clock' -or $peerLower -match 'free-running system clock') { continue }
            if (Test-IsDomainTimePeer -Peer $peer -CandidateHosts $candidateHosts -CandidateAddresses $candidateAddresses -DomainName $domainName) {
                continue
            }
            $suspiciousPeers += $peer
        }

        $suspiciousSource = $null
        if ($sourceName) {
            $sourceLower = $sourceName.ToLowerInvariant()
            $isDomainPeer = Test-IsDomainTimePeer -Peer $sourceName -CandidateHosts $candidateHosts -CandidateAddresses $candidateAddresses -DomainName $domainName
            if (-not $isDomainPeer -or $sourceLower -match 'local cmos clock' -or $sourceLower -match 'free-running system clock' -or $sourceLower -match 'vm ic time synchronization provider') {
                $suspiciousSource = $sourceName
            }
        }

        $clientTypeNormalized = $null
        if ($clientType) {
            $clientTypeNormalized = $clientType.ToString().Trim()
        }

        $isPrimaryDomainController = $false
        if ($null -ne $domainRoleInt -and $domainRoleInt -eq 5) { $isPrimaryDomainController = $true }

        if ($domainJoined -and -not $isPrimaryDomainController) {
            $needsWarning = $false
            if ($clientTypeNormalized -and $clientTypeNormalized.ToUpperInvariant() -ne 'NT5DS') {
                $needsWarning = $true
            }
            if (-not $needsWarning -and $suspiciousPeers.Count -gt 0) { $needsWarning = $true }
            if (-not $needsWarning -and $suspiciousSource) { $needsWarning = $true }

            if ($needsWarning) {
                $evidencePieces = @()
                if ($clientTypeNormalized) { $evidencePieces += "Type $clientTypeNormalized" }
                if ($suspiciousSource) { $evidencePieces += "Source $suspiciousSource" }
                if ($suspiciousPeers.Count -gt 0) {
                    $evidencePieces += ("Peers: {0}" -f (($suspiciousPeers | Sort-Object -Unique) -join ', '))
                }
                if (-not $evidencePieces) { $evidencePieces += 'Manual time source detected.' }
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Domain time misconfigured (manual NTP), so Active Directory cannot control system time.' -Evidence ($evidencePieces -join '; ') -Subcategory 'Time Synchronization'
            }
        }
    }

    if ($secureInfo) {
        $scTest = $secureInfo.TestComputerSecureChannel
        $scBroken = $false
        if ($scTest) {
            if ($scTest.Succeeded -eq $true -and $scTest.IsSecure -eq $false) {
                $scBroken = $true
            } elseif ($scTest.Succeeded -eq $true -and $scTest.IsSecure -eq $true) {
                Add-CategoryNormal -CategoryResult $result -Title 'GOOD SecureChannel (verified)' -Subcategory 'Secure Channel'
            }
        }
        if ($secureInfo.NltestScQuery) {
            $outputText = $secureInfo.NltestScQuery.Output -join ' '
            if ($outputText -match 'NO_LOGON_SERVERS' -or $outputText -match 'TRUST_FAILURE' -or $outputText -match 'STATUS=\s*0xC000018D') {
                $scBroken = $true
            }
        }
        if ($scTest -and $scTest.Succeeded -eq $false -and $scTest.Error) {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Secure channel verification failed to run, so machine trust status is unknown.' -Evidence $scTest.Error -Subcategory 'Secure Channel'
        }
        if ($scBroken) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Broken machine secure channel, blocking domain authentication.' -Subcategory 'Secure Channel'
        }
    }

    $noDcReachable = $fullyReachableHosts.Count -eq 0

    if ($kerberosInfo) {
        $kerberosEvents = @()
        if ($kerberosInfo.Events) {
            foreach ($event in $kerberosInfo.Events) {
                if ($event -and -not $event.Error) { $kerberosEvents += $event }
            }
        }

        $failureEvents = $kerberosEvents | Where-Object { $_.Id -in 4768, 4771, 4776 }
        $failureCount = $failureEvents.Count
        if ($kerberosInfo.Parsed -and $kerberosInfo.Parsed.HasTgt -ne $true) {
            $title = "Kerberos TGT not present, breaking Active Directory authentication."
            $evidencePartsBuilder = [System.Text.StringBuilder]::new()
            Add-StringFragment -Builder $evidencePartsBuilder -Fragment 'klist output missing krbtgt ticket'
            if ($kerberosInfo.Parsed.PSObject.Properties['TgtRealm'] -and $kerberosInfo.Parsed.TgtRealm) {
                Add-StringFragment -Builder $evidencePartsBuilder -Fragment ("Expected realm: {0}" -f $kerberosInfo.Parsed.TgtRealm)
            }
            if ($noDcReachable) { Add-StringFragment -Builder $evidencePartsBuilder -Fragment 'likely off network' }
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence $evidencePartsBuilder.ToString() -Subcategory 'Kerberos'
        }

        if ($failureCount -gt 0) {
            $severity = if ($failureCount -ge 15) { 'high' } else { 'medium' }
            if ($noDcReachable -and $severity -eq 'high') { $severity = 'medium' }
            $messageBuilder = [System.Text.StringBuilder]::new()
            $null = $messageBuilder.Append(("Kerberos authentication failures detected ({0}), breaking Active Directory authentication" -f $failureCount))
            if ($timeSkewHigh -and ($failureEvents | Where-Object { $_.Message -match 'KRB_AP_ERR_SKEW' })) {
                $null = $messageBuilder.Append(' related to time skew')
            } elseif ($noDcReachable) {
                $null = $messageBuilder.Append('; DC unreachable')
            }
            $failureGroups = $failureEvents | Group-Object -Property Id
            $failureSummaryParts = [System.Collections.Generic.List[string]]::new()
            foreach ($group in $failureGroups) {
                $null = $failureSummaryParts.Add(("{0}x{1}" -f $group.Count, $group.Name))
            }

            $failureSummary = ($failureSummaryParts -join ', ')
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $messageBuilder.ToString() -Evidence $failureSummary -Subcategory 'Kerberos'
        }
    }

    if ($gpoInfo) {
        $gpResult = $gpoInfo.GpResult
        $gpoEvents = @()
        if ($gpoInfo.Events) {
            foreach ($event in $gpoInfo.Events) {
                if ($event -and -not $event.Error) { $gpoEvents += $event }
            }
        }

        $gpResultSuccess = $false
        if ($gpResult -and $gpResult.Succeeded -eq $true) { $gpResultSuccess = $true }

        if ($gpResultSuccess -and $gpoEvents.Count -eq 0) {
            Add-CategoryNormal -CategoryResult $result -Title 'GOOD GPO (processed successfully)' -Subcategory 'Group Policy'
        } else {
            $severity = 'medium'
            if ($gpoEvents.Count -ge 5 -and $sharesFailingHosts.Count -gt 0) { $severity = 'high' }
            $title = "GPO processing errors, so device policies aren't applied"
            if ($timeSkewHigh) {
                $titleBuilder = [System.Text.StringBuilder]::new()
                $null = $titleBuilder.Append($title)
                $null = $titleBuilder.Append(' related to time skew')
                $title = $titleBuilder.ToString()
            }
            $evidenceBuilder = [System.Text.StringBuilder]::new()
            if ($gpResult -and $gpResult.Output) { Add-StringFragment -Builder $evidenceBuilder -Fragment (($gpResult.Output | Select-Object -First 3) -join ' | ') }
            if ($gpResult -and $gpResult.Error) { Add-StringFragment -Builder $evidenceBuilder -Fragment $gpResult.Error }
            if ($gpoEvents.Count -gt 0) {
                $eventGroups = $gpoEvents | Group-Object -Property Id
                $eventSummaryParts = [System.Collections.Generic.List[string]]::new()
                foreach ($group in $eventGroups) {
                    $null = $eventSummaryParts.Add(("{0}x{1}" -f $group.Count, $group.Name))
                }

                $eventSummary = ($eventSummaryParts -join ', ')
                if ($eventSummary) { Add-StringFragment -Builder $evidenceBuilder -Fragment $eventSummary }
            }
            if ($evidenceBuilder.Length -eq 0) { Add-StringFragment -Builder $evidenceBuilder -Fragment 'GPO data unavailable' }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidenceBuilder.ToString() -Subcategory 'Group Policy'
        }
    }

    $identityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'identity'
    if ($identityArtifact) {
        $identityPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $identityArtifact)
        if ($identityPayload -and $identityPayload.DsRegCmd) {
            $text = if ($identityPayload.DsRegCmd -is [string[]]) { $identityPayload.DsRegCmd -join "`n" } else { [string]$identityPayload.DsRegCmd }
            if ($text -match 'AzureAdJoined\s*:\s*YES') {
                Add-CategoryNormal -CategoryResult $result -Title 'Azure AD join detected' -Subcategory 'Discovery'
            }
        }
    }

    $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
    if ($eventsArtifact) {
        $eventsPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
        if ($eventsPayload -and $eventsPayload.GroupPolicy) {
            $groupPolicyLog = $eventsPayload.GroupPolicy
            if ($groupPolicyLog.Error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to read Group Policy event log, so device policy failures may be hidden.' -Evidence $groupPolicyLog.Error -Subcategory 'Group Policy'
            } else {
                $entries = if ($groupPolicyLog -is [System.Collections.IEnumerable] -and -not ($groupPolicyLog -is [string])) { @($groupPolicyLog) } else { @($groupPolicyLog) }
                $sysvolMatches = $entries | Where-Object { $_.Message -match '(?i)\\\\[^\r\n]+\\(SYSVOL|NETLOGON)' -or $_.Message -match '(?i)The network path was not found' -or $_.Message -match '(?i)The system cannot find the path specified' }
                if ($sysvolMatches.Count -gt 0) {
                    $selectedSysvolMatches = $sysvolMatches | Select-Object -First 3
                    $sysvolEvidence = [System.Collections.Generic.List[string]]::new()
                    foreach ($entry in $selectedSysvolMatches) {
                        $null = $sysvolEvidence.Add(("[{0}] {1}" -f $entry.Id, $entry.Message))
                    }

                    $evidence = ($sysvolEvidence -join "`n")
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title "Group Policy errors accessing SYSVOL/NETLOGON, so device policies aren't applied." -Evidence $evidence -Subcategory 'Group Policy'
                }

                $gpoFailures = $entries | Where-Object { $_.Id -in 1058, 1030, 1502, 1503 }
                if ($gpoFailures.Count -gt 0) {
                    $selectedGpoFailures = $gpoFailures | Select-Object -First 3
                    $gpoFailureEvidence = [System.Collections.Generic.List[string]]::new()
                    foreach ($entry in $selectedGpoFailures) {
                        $null = $gpoFailureEvidence.Add(("[{0}] {1}" -f $entry.Id, $entry.Message))
                    }

                    $evidence = ($gpoFailureEvidence -join "`n")
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title "Group Policy processing failures detected, so device policies aren't applied." -Evidence $evidence -Subcategory 'Group Policy'
                }
            }
        }
    }

    return $result
}
