. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ActiveDirectoryHeuristics {
  param(
    [hashtable]$Raw,
    [hashtable]$Summary
  )

  if (-not $Raw) { return }
  if (-not $Summary) { return }

  $adDomainText    = $Raw['ad_domain']
  $adDiscoveryText = $Raw['ad_dc']
  $adPortText      = $Raw['ad_ports']
  $adSysvolText    = $Raw['ad_sysvol']
  $adTimeText      = $Raw['ad_time']
  $adKerberosText  = $Raw['ad_kerberos']
  $adSecureText    = $Raw['ad_secure']
  $adGpoText       = $Raw['ad_gpo']

  $hasAdData = $adDomainText -or $adDiscoveryText -or $adPortText -or $adSysvolText -or $adTimeText -or $adKerberosText -or $adSecureText -or $adGpoText

  if ($hasAdData) {
    $adDomainJoined = $null
    $domainName = $null
    $domainDnsName = $null
    $userDnsDomain = $null
    $logonServer = $null
    $domainCandidatesSet = [System.Collections.Generic.HashSet[string]]::new()
    $forestCandidatesSet = [System.Collections.Generic.HashSet[string]]::new()
    $domainEvidenceLines = @()

    if ($adDomainText) {
      $domainLines = [regex]::Split($adDomainText,'\r?\n')
      foreach ($line in $domainLines) {
        if ($null -eq $line) { continue }
        $trim = $line.Trim()
        if ($trim) { $domainEvidenceLines += $trim }

        if ($trim -match '^(?i)PartOfDomain\s*:\s*(.+)$') {
          $value = $matches[1].Value.Trim()
          if ($value -and $value -notmatch '^(?i)unknown$') {
            $adDomainJoined = Get-BoolFromString $value
          }
          continue
        }

        if ($trim -match '^(?i)DomainDnsName\s*:\s*(.+)$') {
          $domainDnsName = $matches[1].Value.Trim()
          continue
        }

        if ($trim -match '^(?i)Domain\s*:\s*(.+)$') {
          $domainName = $matches[1].Value.Trim()
          continue
        }

        if ($trim -match '^(?i)USERDNSDOMAIN\s*:\s*(.+)$') {
          $userDnsDomain = $matches[1].Value.Trim()
          continue
        }

        if ($trim -match '^(?i)LOGONSERVER\s*:\s*(.+)$') {
          $logonServer = $matches[1].Value.Trim()
          continue
        }

        if ($trim -match '^(?i)DomainCandidates\s*:\s*(.+)$') {
          $RawValue = $matches[1].Value.Trim()
          if ($RawValue -and $RawValue -notmatch '^\(none\)$') {
            foreach ($piece in ($RawValue -split ',|;')) {
              $normalized = Normalize-AdDomain $piece
              if ($normalized) { $null = $domainCandidatesSet.Add($normalized) }
            }
          }
          continue
        }

        if ($trim -match '^(?i)ForestCandidates\s*:\s*(.+)$') {
          $RawValue = $matches[1].Value.Trim()
          if ($RawValue -and $RawValue -notmatch '^\(none\)$') {
            foreach ($piece in ($RawValue -split ',|;')) {
              $normalized = Normalize-AdDomain $piece
              if ($normalized) { $null = $forestCandidatesSet.Add($normalized) }
            }
          }
          continue
        }
      }
    }

    $domainEvidenceText = if ($domainEvidenceLines -and $domainEvidenceLines.Count -gt 0) { ($domainEvidenceLines | Select-Object -First 40) -join "`n" } else { Get-FirstLines $adDomainText 40 }

    $normalizedDomainName = Normalize-AdDomain $domainName
    if ($normalizedDomainName) {
      if ($normalizedDomainName -eq 'workgroup' -and $null -eq $adDomainJoined) { $adDomainJoined = $false }
      $null = $domainCandidatesSet.Add($normalizedDomainName)
    }

    $normalizedDomainDns = Normalize-AdDomain $domainDnsName
    if ($normalizedDomainDns) {
      $null = $domainCandidatesSet.Add($normalizedDomainDns)
      $null = $forestCandidatesSet.Add($normalizedDomainDns)
    }

    $normalizedUserDns = Normalize-AdDomain $userDnsDomain
    if ($normalizedUserDns) {
      $null = $domainCandidatesSet.Add($normalizedUserDns)
      $null = $forestCandidatesSet.Add($normalizedUserDns)
    }

    foreach ($candidate in $domainCandidatesSet) { $null = $forestCandidatesSet.Add($candidate) }

    $domainCandidates = @($domainCandidatesSet) | Sort-Object -Unique
    $forestCandidates = @($forestCandidatesSet) | Sort-Object -Unique

    if (-not $domainDnsName) {
      if ($userDnsDomain) {
        $domainDnsName = $userDnsDomain
      } elseif ($domainCandidates -and $domainCandidates.Count -gt 0) {
        $domainDnsName = $domainCandidates[0]
      }
    }

    if (-not $forestCandidates -or $forestCandidates.Count -eq 0) {
      $forestCandidates = $domainCandidates
    }

    if ($null -eq $adDomainJoined) {
      $nonWorkgroupCandidates = $domainCandidates | Where-Object { $_ -and $_ -ne 'workgroup' }
      if ($nonWorkgroupCandidates -and $nonWorkgroupCandidates.Count -gt 0) {
        $adDomainJoined = $true
      } elseif (($adDiscoveryText -and $adDiscoveryText -match 'DiscoveredDC') -or ($adPortText -and $adPortText -match 'PortResult')) {
        $adDomainJoined = $true
      } else {
        $adDomainJoined = $false
      }
    }

    if ($domainDnsName) { $Summary.Domain = $domainDnsName }
    if ($adDomainJoined -ne $null) { $Summary.DomainJoined = $adDomainJoined }
    if ($logonServer) { $Summary.LogonServer = $logonServer }

    if (-not $adDomainJoined) {
      Add-Normal "AD/Status" "GOOD AD not applicable (device not domain-joined)." $domainEvidenceText
    } else {
        $adConnectivityRootCause = $false
        $adTimeSkewHigh = $false
        $adTimeEvidence = ''

      $dcMap = @{}
      $srvStatus = @{}
      $nltestResults = New-Object System.Collections.Generic.List[pscustomobject]
      if ($adDiscoveryText) {
        $discoveryLines = [regex]::Split($adDiscoveryText,'\r?\n')
        foreach ($line in $discoveryLines) {
          if ($null -eq $line) { continue }
          $trim = $line.Trim()
          if (-not $trim) { continue }

          if ($trim -match '^NLTEST\.DSGETDC\.Result\s*:\s*(?<result>[^|]+)\s*\|\s*Domain=(?<domain>[^|]+)\s*\|\s*ExitCode=(?<code>[^|]+)') {
            $nltestResults.Add([pscustomobject]@{ Command = 'dsgetdc'; Domain = $matches['domain'].Value.Trim(); Result = $matches['result'].Value.Trim(); ExitCode = $matches['code'].Value.Trim() })
            continue
          }

          if ($trim -match '^NLTEST\.DCLIST\.Result\s*:\s*(?<result>[^|]+)\s*\|\s*Domain=(?<domain>[^|]+)\s*\|\s*ExitCode=(?<code>[^|]+)') {
            $nltestResults.Add([pscustomobject]@{ Command = 'dclist'; Domain = $matches['domain'].Value.Trim(); Result = $matches['result'].Value.Trim(); ExitCode = $matches['code'].Value.Trim() })
            continue
          }

          if ($trim -match '^SRVLookup\s*:\s*(?<srv>[^|]+)\s*\|\s*Status=(?<status>[^|]+)(?:\s*\|\s*Count=(?<count>[^|]+))?(?:\s*\|\s*Error=(?<error>.+))?$') {
            $srvName = $matches['srv'].Value.Trim()
            $srvStatus[$srvName] = [pscustomobject]@{
              Status = $matches['status'].Value.Trim()
              Count  = if ($matches['count'].Success) { $matches['count'].Value.Trim() } else { '' }
              Error  = if ($matches['error'].Success) { $matches['error'].Value.Trim() } else { '' }
            }
            continue
          }

          if ($trim -match '^DiscoveredDC\s*:\s*(?<dc>[^|]+)(?:\|\s*(?<rest>.*))?$') {
            $dcNameRaw = $matches['dc'].Value.Trim()
            $dcNormalized = Normalize-AdHost $dcNameRaw
            if ($dcNormalized) {
              if (-not $dcMap.ContainsKey($dcNormalized)) {
                $dcMap[$dcNormalized] = [pscustomobject]@{
                  Name      = $dcNormalized
                  Display   = $dcNameRaw
                  Sources   = [System.Collections.Generic.HashSet[string]]::new()
                  Addresses = [System.Collections.Generic.HashSet[string]]::new()
                }
              }
              $source = 'Unknown'
              if ($matches['rest'].Success -and $matches['rest'].Value -match 'Source=([^|]+)') {
                $source = $matches[1].Value.Trim()
              }
              $null = $dcMap[$dcNormalized].Sources.Add($source)
            }
            continue
          }

          if ($trim -match '^DiscoveredDCAddress\s*:\s*(?<addr>[^|]+)\s*\|\s*Domain=(?<domain>[^|]+)\s*\|\s*DC=(?<dc>.+)$') {
            $addr = $matches['addr'].Value.Trim()
            $dcNameRaw = $matches['dc'].Value.Trim()
            $dcNormalized = Normalize-AdHost $dcNameRaw
            if ($dcNormalized -and $dcMap.ContainsKey($dcNormalized)) {
              $null = $dcMap[$dcNormalized].Addresses.Add($addr)
            }
            continue
          }
        }
      }

      $dcPortMap = @{}
      $portsAnyAttempt = $false
      $portsAnySuccess = $false
      if ($adPortText) {
        $portLines = [regex]::Split($adPortText,'\r?\n')
        foreach ($line in $portLines) {
          if ($null -eq $line) { continue }
          $trim = $line.Trim()
          if (-not $trim) { continue }

          if ($trim -match '^(?i)PortResult\s*:\s*(?<dc>[^|]+)\|\s*(?<rest>.+)$') {
            $portsAnyAttempt = $true
            $dcNameRaw = $matches['dc'].Value.Trim()
            $dcNormalized = Normalize-AdHost $dcNameRaw
            $rest = $matches['rest'].Value
            $fields = ($rest -split '\|') | ForEach-Object { $_.Trim() }
            $portNumber = $null
            $successValue = $null
            $errorValue = $null
            $remoteAddress = $null

            foreach ($field in $fields) {
              if ($field -match '^(?i)Port=(\d+)') { $portNumber = [int]$matches[1].Value; continue }
              if ($field -match '^(?i)Success=(.+)$') {
                $successRaw = $matches[1].Value.Trim()
                if ($successRaw -match '^(?i)True$') { $successValue = $true }
                elseif ($successRaw -match '^(?i)False$') { $successValue = $false }
                elseif ($successRaw -match '^(?i)Error$') { $successValue = $null }
                continue
              }
              if ($field -match '^(?i)Error=(.+)$') { $errorValue = $matches[1].Value.Trim(); continue }
              if ($field -match '^(?i)RemoteAddress=(.+)$') { $remoteAddress = $matches[1].Value.Trim(); continue }
            }

            if ($dcNormalized) {
              if (-not $dcPortMap.ContainsKey($dcNormalized)) {
                $dcPortMap[$dcNormalized] = [pscustomobject]@{
                  Name            = $dcNormalized
                  Display         = $dcNameRaw
                  Ports           = @{}
                  RemoteAddresses = [System.Collections.Generic.HashSet[string]]::new()
                }
              }

              if ($portNumber) {
                $dcPortMap[$dcNormalized].Ports[$portNumber] = [pscustomobject]@{ Success = $successValue; Error = $errorValue }
                if ($successValue -eq $true) { $portsAnySuccess = $true }
              }

              if ($remoteAddress) { $null = $dcPortMap[$dcNormalized].RemoteAddresses.Add($remoteAddress) }
            }
          }
        }
      }

      $sysvolExists = $false
      $netlogonExists = $false
      $sysvolErrors = @()
      if ($adSysvolText) {
        $sysvolLines = [regex]::Split($adSysvolText,'\r?\n')
        foreach ($line in $sysvolLines) {
          if ($null -eq $line) { continue }
          $trim = $line.Trim()
          if (-not $trim) { continue }

          if ($trim -match '^ShareExists\s*:\s*(?<share>[^|]+)\s*\|\s*Path=(?<path>[^|]+)\s*\|\s*Exists=(?<exists>[^|]+)$') {
            $share = $matches['share'].Value.Trim().ToUpperInvariant()
            $existsValue = $matches['exists'].Value.Trim()
            if ($share -eq 'SYSVOL') {
              if ($existsValue -match '^(?i)true$') { $sysvolExists = $true }
              elseif ($existsValue -notmatch '^(?i)false$') { $sysvolErrors += $trim }
            } elseif ($share -eq 'NETLOGON') {
              if ($existsValue -match '^(?i)true$') { $netlogonExists = $true }
              elseif ($existsValue -notmatch '^(?i)false$') { $sysvolErrors += $trim }
            }
            continue
          }

          if ($trim -match '^ShareError\s*:\s*(?<share>[^|]+)\s*\|\s*Error=(?<err>.+)$') {
            $sysvolErrors += $trim
            continue
          }
        }
      }

      $sysvolAccessible = ($sysvolExists -or $netlogonExists)

      $timeStatusExit = $null
      $timePeersExit = $null
      $timeSource = $null
      $timeOffsetSeconds = $null
      $timeErrors = @()
      if ($adTimeText) {
        if ($adTimeText -match 'StatusExitCode\s*:\s*([^
  ]+)') { $timeStatusExit = $matches[1].Value.Trim() }
        if ($adTimeText -match 'PeersExitCode\s*:\s*([^
  ]+)') { $timePeersExit = $matches[1].Value.Trim() }
        if ($adTimeText -match 'PhaseOffsetSeconds\s*:\s*([^
  ]+)') {
          $offsetRaw = $matches[1].Value.Trim()
          $offsetParsed = 0.0
          if ([double]::TryParse($offsetRaw, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$offsetParsed)) {
            $timeOffsetSeconds = $offsetParsed
          }
        }
        if ($adTimeText -match 'TimeSource\s*:\s*([^
  ]+)') { $timeSource = $matches[1].Value.Trim() }
        if ($adTimeText -match '(?i)The service has not been started|Access is denied|Unable to open the service|0x800705b4') { $timeErrors += $matches[0].Value.Trim() }
      }

      $secureChannelResult = $null
      if ($adSecureText -match 'SecureChannelResult\s*:\s*(\w+)') {
        $resultValue = $matches[1].Value.Trim()
        if ($resultValue -match '^(?i)true$') { $secureChannelResult = $true }
        elseif ($resultValue -match '^(?i)false$') { $secureChannelResult = $false }
        elseif ($resultValue -match '^(?i)error$') { $secureChannelResult = $null }
      }

      $secureChannelNltestExit = $null
      if ($adSecureText -match 'SecureChannelNltestExitCode\s*:\s*([^
  ]+)') { $secureChannelNltestExit = $matches[1].Value.Trim() }

      $secureChannelNltestFailure = $false
      if ($adSecureText -match '(?i)TRUST_FAILURE|NO_LOGON_SERVERS|STATUS_TRUST_FAILURE|STATUS_ACCESS_DENIED') { $secureChannelNltestFailure = $true }

      $kerberosTgtPresent = $false
      if ($adKerberosText -and ($adKerberosText -match 'krbtgt/')) { $kerberosTgtPresent = $true }
      $kerberosEventCount = 0
      if ($adKerberosText -match 'KerberosEventCount\s*:\s*(\d+)') { $kerberosEventCount = [int]$matches[1].Value }
      $kerberosFailureCount = 0
      $kerberosSkewCount = 0
      if ($adKerberosText) {
        $kerbLines = [regex]::Split($adKerberosText,'\r?\n')
        foreach ($line in $kerbLines) {
          if ($null -eq $line) { continue }
          $trim = $line.Trim()
          if (-not $trim) { continue }
          if ($trim -match '^KerberosEvent\s*:\s*Id=(?<id>\d+);\s*Time=(?<time>[^;]+);\s*Provider=(?<provider>[^;]+);\s*Message=(?<msg>.+)$') {
            $msg = $matches['msg'].Value
            $failureDetected = $false
            if ($msg -match '(?i)KRB_AP_ERR_SKEW') { $kerberosSkewCount++ }
            if ($msg -match '(?i)Failure') {
              if ($msg -match '(?i)Failure Code\s*:\s*(0x[0-9A-Fa-f]+)') {
                if ($matches[1].Value -ne '0x0') { $failureDetected = $true }
              } elseif ($msg -match '(?i)Status\s*:\s*(0x[0-9A-Fa-f]+)') {
                if ($matches[1].Value -ne '0x0') { $failureDetected = $true }
              } else {
                $failureDetected = $true }
            }
            if ($failureDetected) { $kerberosFailureCount++ }
          }
        }
      }

      $gpoEventCount = 0
      if ($adGpoText -match 'GPOEventCount\s*:\s*(\d+)') { $gpoEventCount = [int]$matches[1].Value }
      $gpFailureDetected = $false
      $gpSuccessDetected = $false
      if ($adGpoText) {
        if ($adGpoText -match '(?i)The processing of Group Policy failed') { $gpFailureDetected = $true }
        if ($adGpoText -match '(?i)Group Policy was applied successfully') { $gpSuccessDetected = $true }
      }

      $discoveredDcEntries = $dcMap.Keys | ForEach-Object { $dcMap[$_] }
      $srvSuccess = $false
      foreach ($entry in $srvStatus.Values) {
        if ($entry.Status -eq 'Success') { $srvSuccess = $true; break }
      }
      $srvAttempted = $srvStatus.Count -gt 0
      $srvAllFail = $srvAttempted -and (-not $srvSuccess)

      $nltestAnySuccess = $false
      foreach ($res in $nltestResults) {
        if ($res.Result -match 'Success') { $nltestAnySuccess = $true; break }
      }
      $nltestAttempted = $nltestResults.Count -gt 0
      $nltestAllFail = $nltestAttempted -and (-not $nltestAnySuccess)

      $adDiscoverySummaryLines = @()
      foreach ($dcEntry in $discoveredDcEntries | Sort-Object Name) {
        $sourceText = ''
        if ($dcEntry.Sources -and $dcEntry.Sources.Count -gt 0) { $sourceText = (@($dcEntry.Sources) -join ', ') }
        $addrText = ''
        if ($dcEntry.Addresses -and $dcEntry.Addresses.Count -gt 0) { $addrText = (@($dcEntry.Addresses) -join ', ') }
        $line = $dcEntry.Display
        if ($sourceText) { $line += " (Sources: $sourceText)" }
        if ($addrText) { $line += " (Addr: $addrText)" }
        $adDiscoverySummaryLines += $line
      }
      $adDiscoveryEvidence = ($adDiscoverySummaryLines + '' + (Get-FirstLines $adDiscoveryText 40)) -join "`n"

      $portEvidenceLines = @()
      foreach ($dcEntry in $dcPortMap.Values | Sort-Object Name) {
        $portSummaries = @()
        foreach ($p in @(88,389,445,135)) {
          if ($dcEntry.Ports.ContainsKey($p)) {
            $success = $dcEntry.Ports[$p].Success
            if ($success -eq $true) { $portSummaries += "$p:OK" }
            elseif ($success -eq $false) { $portSummaries += "$p:Fail" }
            else { $portSummaries += "$p:Error" }
          } else {
            $portSummaries += "$p:NoData"
          }
        }
        $addrText = ''
        if ($dcEntry.RemoteAddresses -and $dcEntry.RemoteAddresses.Count -gt 0) { $addrText = " Addr=" + (@($dcEntry.RemoteAddresses) -join ',') }
        $portEvidenceLines += ("{0} -> {1}{2}" -f $dcEntry.Display, ($portSummaries -join ' '), $addrText)
      }
      $adPortEvidence = ($portEvidenceLines + '' + (Get-FirstLines $adPortText 40)) -join "`n"

      $sysvolEvidenceLines = @()
      $sysvolEvidenceLines += ("SYSVOL Exists: " + ([string]$sysvolExists))
      $sysvolEvidenceLines += ("NETLOGON Exists: " + ([string]$netlogonExists))
      if ($sysvolErrors -and $sysvolErrors.Count -gt 0) { $sysvolEvidenceLines += $sysvolErrors }
      $sysvolEvidenceLines += Get-FirstLines $adSysvolText 30
      $adSysvolEvidence = $sysvolEvidenceLines -join "`n"

      $timeEvidenceLines = @()
      if ($timeOffsetSeconds -ne $null) { $timeEvidenceLines += ("PhaseOffsetSeconds: {0}" -f $timeOffsetSeconds) }
      if ($timeSource) { $timeEvidenceLines += ("TimeSource: {0}" -f $timeSource) }
      if ($timeStatusExit) { $timeEvidenceLines += ("StatusExitCode: {0}" -f $timeStatusExit) }
      if ($timeErrors -and $timeErrors.Count -gt 0) { $timeEvidenceLines += $timeErrors }
      $timeEvidenceLines += Get-FirstLines $adTimeText 40
      $adTimeEvidence = $timeEvidenceLines -join "`n"

      $secureEvidenceLines = @()
      if ($null -ne $secureChannelResult) { $secureEvidenceLines += ("SecureChannelResult: {0}" -f $secureChannelResult) }
      if ($secureChannelNltestExit) { $secureEvidenceLines += ("NLTEST ExitCode: {0}" -f $secureChannelNltestExit) }
      $secureEvidenceLines += Get-FirstLines $adSecureText 40
      $adSecureEvidence = $secureEvidenceLines -join "`n"

      $kerberosEvidenceLines = @()
      $kerberosEvidenceLines += ("TGT Present: " + ([string]$kerberosTgtPresent))
      $kerberosEvidenceLines += ("Kerberos Failure Events: {0}" -f $kerberosFailureCount)
      if ($kerberosSkewCount -gt 0) { $kerberosEvidenceLines += ("KRB_AP_ERR_SKEW events: {0}" -f $kerberosSkewCount) }
      $kerberosEvidenceLines += Get-FirstLines $adKerberosText 40
      $kerberosEvidence = $kerberosEvidenceLines -join "`n"

      $gpoEvidenceLines = @()
      $gpoEvidenceLines += ("GPOEventCount: {0}" -f $gpoEventCount)
      if ($gpFailureDetected) { $gpoEvidenceLines += "gpresult reported failures." }
      $gpoEvidenceLines += Get-FirstLines $adGpoText 60
      $adGpoEvidence = $gpoEvidenceLines -join "`n"

      $noDcDiscovered = ($dcMap.Count -eq 0)
      if ($noDcDiscovered -and $srvAllFail -and $nltestAllFail) {
        Add-Issue 'high' 'AD/Discovery' 'No DC discovered.' $adDiscoveryEvidence
        $adConnectivityRootCause = $true
      }

      if ($srvAllFail) {
        Add-Issue 'high' 'AD/DNS' 'AD SRV records not resolvable.' $adDiscoveryEvidence
        $adConnectivityRootCause = $true
        } elseif ($srvSuccess) {
          Add-Normal 'AD/DNS' 'GOOD AD/DNS (SRV resolves).' $adDiscoveryEvidence
        }

        if ($portsAnyAttempt -and -not $portsAnySuccess) {
          Add-Issue 'high' 'AD/Reachability' 'Cannot reach any DC on required ports.' $adPortEvidence
          $adConnectivityRootCause = $true
        } elseif ($portsAnySuccess -and $sysvolAccessible) {
          Add-Normal 'AD/Reachability' 'GOOD AD/Reachability (≥1 DC reachable + SYSVOL).' $adPortEvidence
        }

        if ($portsAnySuccess -and -not $sysvolAccessible) {
          Add-Issue 'medium' 'AD/SYSVOL' 'Domain shares unreachable (DFS/DNS/auth).' $adSysvolEvidence
        }

      $timeUnsynced = $false
      if ($timeStatusExit -and $timeStatusExit -notin @('0','0x0')) { $timeUnsynced = $true }
      if ($timeErrors -and $timeErrors.Count -gt 0) { $timeUnsynced = $true }
      if ($timeSource -and $timeSource -match '(?i)local cmos clock|free-running|local machine clock') { $timeUnsynced = $true }

      if ($timeOffsetSeconds -ne $null -and [math]::Abs($timeOffsetSeconds) -gt 300) {
        Add-Issue 'high' 'AD/Time' ("Kerberos time skew: offset {0}s (source {1})." -f [math]::Round($timeOffsetSeconds,2), (if ($timeSource) { $timeSource } else { 'Unknown' })) $adTimeEvidence
        $adTimeSkewHigh = $true
      } elseif ($timeUnsynced) {
        Add-Issue 'high' 'AD/Time' 'Kerberos time skew: time service unsynchronized.' $adTimeEvidence
        $adTimeSkewHigh = $true
        } elseif ($timeOffsetSeconds -ne $null -and [math]::Abs($timeOffsetSeconds) -le 300 -and -not $timeUnsynced) {
          Add-Normal 'AD/Time' 'GOOD Time (skew ≤5m).' $adTimeEvidence
        }

      $secureChannelBroken = $false
      if ($secureChannelResult -eq $false) { $secureChannelBroken = $true }
      if ($secureChannelNltestExit -and $secureChannelNltestExit -notin @('0','0x0')) { $secureChannelBroken = $true }
      if ($secureChannelNltestFailure) { $secureChannelBroken = $true }

      if ($secureChannelBroken) {
        Add-Issue 'high' 'AD/SecureChannel' 'Broken machine secure channel.' $adSecureEvidence
        $adConnectivityRootCause = $true
      } elseif ($secureChannelResult -eq $true -and -not $secureChannelNltestFailure) {
        Add-Normal 'AD/SecureChannel' 'GOOD SecureChannel (verified).' $adSecureEvidence
      }

        if ($kerberosFailureCount -gt 0) {
          $kerberosSeverity = if ($kerberosFailureCount -ge 10) { 'high' } else { 'medium' }
          if ($adConnectivityRootCause -or ($portsAnyAttempt -and -not $portsAnySuccess)) { $kerberosSeverity = 'medium' }
          $kerberosMessage = "Kerberos failures ({0} recent 4768/4771/4776 events)." -f $kerberosFailureCount
          if ($kerberosSkewCount -gt 0) {
            $kerberosMessage += ' Includes KRB_AP_ERR_SKEW.'
          }
          if ($adTimeSkewHigh -and $kerberosSeverity -eq 'high') { $kerberosSeverity = 'medium' }
          if ($adTimeSkewHigh -and ($kerberosMessage -notmatch 'Related to time skew')) { $kerberosMessage += ' Related to time skew.' }
          Add-Issue $kerberosSeverity 'AD/Kerberos' $kerberosMessage $kerberosEvidence
        } elseif (-not $kerberosTgtPresent) {
          $severity = 'medium'
          Add-Issue $severity 'AD/Kerberos' 'No TGT cached; device may be offline from the domain.' $kerberosEvidence
        }

      if ($gpoEventCount -gt 0 -or $gpFailureDetected) {
          $gpoSeverity = if ($gpoEventCount -ge 5 -and -not $sysvolAccessible) { 'high' } else { 'medium' }
          if ($adConnectivityRootCause -and $gpoSeverity -eq 'high') { $gpoSeverity = 'medium' }
          if ($adTimeSkewHigh -and $gpoSeverity -eq 'high') { $gpoSeverity = 'medium' }
          $gpoMessage = "Group Policy errors detected ({0} recent 1058/1030 events)." -f $gpoEventCount
          if ($adTimeSkewHigh) { $gpoMessage += ' Related to time skew.' }
          Add-Issue $gpoSeverity 'AD/GPO' $gpoMessage $adGpoEvidence
        } elseif ($gpSuccessDetected) {
        Add-Normal 'AD/GPO' 'GOOD GPO (processed successfully).' $adGpoEvidence
      }
    }
  }

}
