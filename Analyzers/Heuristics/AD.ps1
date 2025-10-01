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
                }
            }
        }
    }

    if (-not $domainStatus) {
        Write-HeuristicDebug -Source 'AD' -Message 'Domain status unavailable; reporting collection issue'
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'AD health data unavailable' -Subcategory 'Collection'
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
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'AD SRV records not resolvable.' -Evidence $evidence -Subcategory 'DNS Discovery'
    }

    if (-not $srvSuccess -and -not $nltestSuccess -and $discovery) {
        $evidence = @()
        if ($discovery.DsGetDc) {
            if ($discovery.DsGetDc.Error) { $evidence += "dsgetdc: $($discovery.DsGetDc.Error)" }
            elseif ($discovery.DsGetDc.Output) { $evidence += "dsgetdc output: $($discovery.DsGetDc.Output -join ' | ')" }
        }
        if ($discovery.DcList) {
            if ($discovery.DcList.Error) { $evidence += "dclist: $($discovery.DcList.Error)" }
            elseif ($discovery.DcList.Output) { $evidence += "dclist output: $($discovery.DcList.Output -join ' | ')" }
        }
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'No DC discovered.' -Evidence ($evidence -join '; ') -Subcategory 'Discovery'
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
        Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Cannot reach any DC on required ports.' -Evidence (($portMap.Keys | Sort-Object) -join ', ') -Subcategory 'Connectivity'
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
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Domain shares unreachable (DFS/DNS/auth).' -Evidence (($sharesFailingHosts | Sort-Object -Unique) -join ', ') -Subcategory 'SYSVOL'
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
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Kerberos time skew.' -Evidence ("Offset {0} seconds" -f [math]::Round([double]$offset, 2)) -Subcategory 'Time Synchronization'
        } elseif ($synchronized -eq $false -or ($timeInfo.Status -and $timeInfo.Status.Succeeded -ne $true)) {
            $timeSkewHigh = $true
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Kerberos time skew.' -Evidence 'Time service not synchronized.' -Subcategory 'Time Synchronization'
        } elseif ($offset -ne $null -and [math]::Abs([double]$offset) -le 300) {
            Add-CategoryNormal -CategoryResult $result -Title 'GOOD Time (skew ≤5m)' -Evidence ("Offset {0} seconds" -f [math]::Round([double]$offset, 2)) -Subcategory 'Time Synchronization'
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
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Secure channel verification failed to run.' -Evidence $scTest.Error -Subcategory 'Secure Channel'
        }
        if ($scBroken) {
            Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Broken machine secure channel.' -Subcategory 'Secure Channel'
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
            $title = 'Kerberos TGT not present'
            $evidenceParts = @('klist output missing krbtgt ticket')
            if ($kerberosInfo.Parsed.PSObject.Properties['TgtRealm'] -and $kerberosInfo.Parsed.TgtRealm) {
                $evidenceParts += "Expected realm: $($kerberosInfo.Parsed.TgtRealm)"
            }
            if ($noDcReachable) { $evidenceParts += 'likely off network' }
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence ($evidenceParts -join '; ') -Subcategory 'Kerberos'
        }

        if ($failureCount -gt 0) {
            $severity = if ($failureCount -ge 15) { 'high' } else { 'medium' }
            if ($noDcReachable -and $severity -eq 'high') { $severity = 'medium' }
            $message = "Kerberos authentication failures detected ($failureCount)"
            if ($timeSkewHigh -and ($failureEvents | Where-Object { $_.Message -match 'KRB_AP_ERR_SKEW' })) {
                $message += ' related to time skew'
            } elseif ($noDcReachable) {
                $message += '; DC unreachable'
            }
            $failureGroups = $failureEvents | Group-Object -Property Id
            $failureSummaryParts = [System.Collections.Generic.List[string]]::new()
            foreach ($group in $failureGroups) {
                $null = $failureSummaryParts.Add(("{0}x{1}" -f $group.Count, $group.Name))
            }

            $failureSummary = ($failureSummaryParts -join ', ')
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $message -Evidence $failureSummary -Subcategory 'Kerberos'
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
            $title = 'GPO processing errors'
            if ($timeSkewHigh) { $title += ' related to time skew' }
            $evidence = @()
            if ($gpResult -and $gpResult.Output) { $evidence += (($gpResult.Output | Select-Object -First 3) -join ' | ') }
            if ($gpResult -and $gpResult.Error) { $evidence += $gpResult.Error }
            if ($gpoEvents.Count -gt 0) {
                $eventGroups = $gpoEvents | Group-Object -Property Id
                $eventSummaryParts = [System.Collections.Generic.List[string]]::new()
                foreach ($group in $eventGroups) {
                    $null = $eventSummaryParts.Add(("{0}x{1}" -f $group.Count, $group.Name))
                }

                $eventSummary = ($eventSummaryParts -join ', ')
                if ($eventSummary) { $evidence += $eventSummary }
            }
            if (-not $evidence) { $evidence = @('GPO data unavailable') }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence ($evidence -join '; ') -Subcategory 'Group Policy'
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
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Unable to read Group Policy event log' -Evidence $groupPolicyLog.Error -Subcategory 'Group Policy'
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
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Group Policy errors accessing SYSVOL/NETLOGON' -Evidence $evidence -Subcategory 'Group Policy'
                }

                $gpoFailures = $entries | Where-Object { $_.Id -in 1058, 1030, 1502, 1503 }
                if ($gpoFailures.Count -gt 0) {
                    $selectedGpoFailures = $gpoFailures | Select-Object -First 3
                    $gpoFailureEvidence = [System.Collections.Generic.List[string]]::new()
                    foreach ($entry in $selectedGpoFailures) {
                        $null = $gpoFailureEvidence.Add(("[{0}] {1}" -f $entry.Id, $entry.Message))
                    }

                    $evidence = ($gpoFailureEvidence -join "`n")
                    Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Group Policy processing failures detected' -Evidence $evidence -Subcategory 'Group Policy'
                }
            }
        }
    }

    return $result
}
