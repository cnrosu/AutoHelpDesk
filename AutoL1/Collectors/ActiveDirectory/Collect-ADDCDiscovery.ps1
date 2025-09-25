. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ADDomainControllerDiscovery {
  param(
    [pscustomobject]$Context
  )

  $ctx = if ($PSBoundParameters.ContainsKey('Context') -and $Context) { $Context } else { Get-ADCollectorContext }

  Write-Output ("Timestamp : {0:o}" -f (Get-Date))
  $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
  Write-Output ("PartOfDomain : {0}" -f $partText)
  if ($ctx.DomainCandidates -and $ctx.DomainCandidates.Count -gt 0) {
    Write-Output ("DomainCandidates : {0}" -f ($ctx.DomainCandidates -join ', '))
  } else {
    Write-Output "DomainCandidates : (none)"
  }
  if ($ctx.ForestCandidates -and $ctx.ForestCandidates.Count -gt 0) {
    Write-Output ("ForestCandidates : {0}" -f ($ctx.ForestCandidates -join ', '))
  } else {
    Write-Output "ForestCandidates : (none)"
  }
  if ($ctx.PartOfDomain -ne $true) {
    Write-Output "Status : Skipped (NotDomainJoined)"
    return
  }

  $domainList = $ctx.DomainCandidates
  if (-not $domainList -or $domainList.Count -eq 0) {
    Write-Output "Status : No domain candidates for discovery."
    return
  }

  foreach ($domain in $domainList) {
    Write-Output ("## nltest /dsgetdc:{0}" -f $domain)
    $dsOutput = nltest /dsgetdc:$domain 2>&1
    $dsExit = $LASTEXITCODE
    Write-Output ("NLTEST.DSGETDC.Result : {0} | Domain={1} | ExitCode={2}" -f (if ($dsExit -eq 0) { 'Success' } else { 'Failure' }), $domain, $dsExit)
    if ($dsOutput) { $dsOutput | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
    $lastDcName = $null
    foreach ($line in $dsOutput) {
      if ($line -match '^\s*DC:\s*\\(?<dc>[^\s]+)') {
        $lastDcName = Normalize-HostName $matches['dc']
        $dcFqdn = ConvertTo-Fqdn $lastDcName $ctx.DomainDnsName
        $record = if ($dcFqdn) { $dcFqdn } else { $lastDcName }
        if ($record) { Write-Output ("DiscoveredDC : {0} | Source=nltest /dsgetdc | Domain={1}" -f $record, $domain) }
      } elseif ($line -match '^\s*Address:\s*\\(?<addr>[^\s]+)') {
        $addr = $matches['addr'].Trim('\\').Trim()
        if ($addr -and $lastDcName) {
          $dcForAddr = ConvertTo-Fqdn $lastDcName $ctx.DomainDnsName
          $addressTarget = if ($dcForAddr) { $dcForAddr } else { $lastDcName }
          Write-Output ("DiscoveredDCAddress : {0} | Domain={1} | DC={2}" -f $addr, $domain, $addressTarget)
        }
      } elseif ($line -match '^\s*Forest Name:\s*(?<forest>\S.*)$') {
        $forestName = Normalize-DomainName $matches['forest']
        if ($forestName) { Write-Output ("DiscoveredForest : {0} | Source=nltest /dsgetdc | Domain={1}" -f $forestName, $domain) }
      } elseif ($line -match '^\s*Site Name:\s*(?<site>\S.*)$') {
        Write-Output ("SiteName : {0} | Domain={1}" -f $matches['site'].Trim(), $domain)
      }
    }
    Write-Output ""

    Write-Output ("## nltest /dclist:{0}" -f $domain)
    $dcList = nltest /dclist:$domain 2>&1
    $dcListExit = $LASTEXITCODE
    Write-Output ("NLTEST.DCLIST.Result : {0} | Domain={1} | ExitCode={2}" -f (if ($dcListExit -eq 0) { 'Success' } else { 'Failure' }), $domain, $dcListExit)
    if ($dcList) { $dcList | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
    foreach ($line in $dcList) {
      if ($line -match '^\s*(?<name>[A-Za-z0-9\-\.]+)(?:\s*\(.*\))?$') {
        $candidate = $matches['name']
        if ($candidate -and $candidate -notmatch '^(Get|The|List|of|Domain|domain|from|completed|successfully)$') {
          $fqdnCandidate = ConvertTo-Fqdn $candidate $ctx.DomainDnsName
          $recorded = if ($fqdnCandidate) { $fqdnCandidate } else { Normalize-HostName $candidate }
          if ($recorded) { Write-Output ("DiscoveredDC : {0} | Source=nltest /dclist | Domain={1}" -f $recorded, $domain) }
        }
      }
    }
    Write-Output ""
  }

  $forestNames = if ($ctx.ForestCandidates -and $ctx.ForestCandidates.Count -gt 0) { $ctx.ForestCandidates } else { $ctx.DomainCandidates }
  if (-not $forestNames) { $forestNames = @() }
  $resolveCmd = Get-Command Resolve-DnsName -ErrorAction SilentlyContinue
  foreach ($forest in $forestNames) {
    foreach ($srvName in @("_ldap._tcp.dc._msdcs.$forest", "_kerberos._tcp.$forest")) {
      if (-not $resolveCmd) {
        Write-Output ("SRVLookup : {0} | Status=CmdUnavailable" -f $srvName)
        Write-Output ""
        continue
      }
      try {
        $srvResults = Resolve-DnsName -Name $srvName -Type SRV -ErrorAction Stop
        if (-not $srvResults) {
          Write-Output ("SRVLookup : {0} | Status=NoRecords" -f $srvName)
        } else {
          $count = $srvResults.Count
          Write-Output ("SRVLookup : {0} | Status=Success | Count={1}" -f $srvName, $count)
          foreach ($record in $srvResults) {
            $target = if ($record.NameTarget) { $record.NameTarget.TrimEnd('.') } else { $null }
            $addresses = @()
            if ($target) {
              try {
                $addresses = [System.Net.Dns]::GetHostAddresses($target) | ForEach-Object { $_.IPAddressToString }
              } catch {
                $addresses = @()
              }
            }
            $addressText = if ($addresses -and $addresses.Count -gt 0) { $addresses -join ', ' } else { '' }
            Write-Output ("SRVRecord : {0} | Target={1} | Port={2} | Priority={3} | Weight={4} | Addresses={5}" -f $srvName, $target, $record.Port, $record.Priority, $record.Weight, $addressText)
            if ($target) {
              Write-Output ("DiscoveredDC : {0} | Source={1} | Domain={2}" -f $target, $srvName, $forest)
            }
          }
        }
      } catch {
        Write-Output ("SRVLookup : {0} | Status=Error | Error={1}" -f $srvName, $_)
      }
      Write-Output ""
    }
  }

  try {
    Write-Output "## nltest /dsgetsite"
    $siteResult = nltest /dsgetsite 2>&1
    if ($siteResult) { $siteResult | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
  } catch {
    Write-Output ("nltest /dsgetsite failed: {0}" -f $_)
  }
  Write-Output ""
  try {
    Write-Output "## nltest /domain_trusts"
    $trustResult = nltest /domain_trusts 2>&1
    if ($trustResult) { $trustResult | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
  } catch {
    Write-Output ("nltest /domain_trusts failed: {0}" -f $_)
  }
}
