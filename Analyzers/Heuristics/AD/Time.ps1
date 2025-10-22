function Add-AdTimeFindings {
    param(
        [Parameter(Mandatory)]
        $Result,
        $TimeInfo,
        [string[]]$CandidateHosts,
        [string[]]$CandidateAddresses,
        [string]$DomainName,
        [bool]$DomainJoined,
        [int]$DomainRoleInt
    )

    $timeSkewHigh = $false
    $clientType = $null
    $clientServersRaw = $null
    $peerEntries = @()
    $sourceRaw = $null

    $timeSkewEvidence = $null

    if ($TimeInfo) {
        $parsed = $TimeInfo.Parsed
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
            $timeSkewEvidence = "Offset {0} seconds" -f [math]::Round([double]$offset, 2)
        } elseif ($synchronized -eq $false -or ($TimeInfo.Status -and $TimeInfo.Status.Succeeded -ne $true)) {
            $timeSkewHigh = $true
            $timeSkewEvidence = 'Time service not synchronized.'
        } elseif ($offset -ne $null -and [math]::Abs([double]$offset) -le 300) {
            Add-CategoryNormal -CategoryResult $Result -Title 'GOOD Time (skew ≤5m)' -Evidence ("Offset {0} seconds" -f [math]::Round([double]$offset, 2)) -Subcategory 'Time Synchronization'
        }

        if ($parsed) {
            if ($parsed.PSObject.Properties['ClientType']) { $clientType = $parsed.ClientType }
            if ($parsed.PSObject.Properties['ClientNtpServer']) { $clientServersRaw = $parsed.ClientNtpServer }
            if ($parsed.PSObject.Properties['PeerEntries'] -and $parsed.PeerEntries) { $peerEntries = $parsed.PeerEntries }
            if ($parsed.PSObject.Properties['Source']) { $sourceRaw = $parsed.Source }
        }
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
        if (Test-IsDomainTimePeer -Peer $peer -CandidateHosts $CandidateHosts -CandidateAddresses $CandidateAddresses -DomainName $DomainName) {
            continue
        }
        $suspiciousPeers += $peer
    }

    $suspiciousSource = $null
    if ($sourceName) {
        $sourceLower = $sourceName.ToLowerInvariant()
        $isDomainPeer = Test-IsDomainTimePeer -Peer $sourceName -CandidateHosts $CandidateHosts -CandidateAddresses $CandidateAddresses -DomainName $DomainName
        if (-not $isDomainPeer -or $sourceLower -match 'local cmos clock' -or $sourceLower -match 'free-running system clock' -or $sourceLower -match 'vm ic time synchronization provider') {
            $suspiciousSource = $sourceName
        }
    }

    $clientTypeNormalized = $null
    if ($clientType) {
        $clientTypeNormalized = $clientType.ToString().Trim()
    }

    $isPrimaryDomainController = $false
    if ($null -ne $DomainRoleInt -and $DomainRoleInt -eq 5) { $isPrimaryDomainController = $true }

    if ($DomainJoined -and -not $isPrimaryDomainController) {
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
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Domain time misconfigured (manual NTP), so Active Directory cannot control system time.' -Evidence ($evidencePieces -join '; ') -Subcategory 'Time Synchronization' -Remediation (Get-AdKerberosSecureChannelTimeRemediation)
        }
    }

    if ($timeSkewHigh -and $timeSkewEvidence) {
        $evidence = $timeSkewEvidence
        Add-CategoryIssue -CategoryResult $Result -Severity 'critical' -Title 'Kerberos/time skew detected (authentication may fail)' -Evidence $evidence -Subcategory 'Time Service' -Remediation (Get-AdKerberosSecureChannelTimeRemediation) -Data @{
            Area = 'AD/Time'
            Kind = 'TimeSkew'
            Time = @{
                TimeSkewHigh = $timeSkewHigh
                ClientType   = $clientType
                SourceName   = $sourceName
                Peers        = $peerEntries
                ManualPeers  = $manualPeers
            }
        
            Discovery = @{
                CandidateHosts     = $CandidateHosts
                CandidateAddresses = $CandidateAddresses
                DomainName         = $DomainName
                DomainJoined       = $DomainJoined
                DomainRoleInt      = $DomainRoleInt
            }
        }
    }

    [pscustomobject]@{
        TimeSkewHigh         = $timeSkewHigh
        SuspiciousPeers      = $suspiciousPeers
        SuspiciousSource     = $suspiciousSource
        ClientTypeNormalized = $clientTypeNormalized
    }
}
