<#
  Common helpers for Active Directory collectors.
#>

function Normalize-DomainName {
  param([string]$Name)

  if (-not $Name) { return $null }
  $trimmed = $Name.Trim()
  if (-not $trimmed) { return $null }
  return $trimmed.TrimEnd('.').ToLowerInvariant()
}

function Normalize-HostName {
  param([string]$Name)

  if (-not $Name) { return $null }
  $result = $Name.Trim()
  if (-not $result) { return $null }
  $result = $result.Trim('\\')
  if (-not $result) { return $null }
  if ($result -like '*\\*') {
    $segments = $result -split '\\'
    $result = $segments[-1]
  }
  return $result.Trim().ToLowerInvariant()
}

function ConvertTo-Fqdn {
  param(
    [string]$Host,
    [string]$Domain
  )

  $normalizedHost = Normalize-HostName $Host
  if (-not $normalizedHost) { return $null }
  if ($normalizedHost.Contains('.')) { return $normalizedHost }

  $normalizedDomain = Normalize-DomainName $Domain
  if ($normalizedDomain) {
    return ("{0}.{1}" -f $normalizedHost, $normalizedDomain)
  }

  return $normalizedHost
}

function Get-ADCollectorContext {
  $ctx = [ordered]@{
    ComputerName     = $env:COMPUTERNAME
    Timestamp        = Get-Date
    PartOfDomain     = $null
    Domain           = $null
    DomainDnsName    = $null
    DomainCandidates = @()
    ForestCandidates = @()
    UserDnsDomain    = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { $null }
    UserDomain       = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { $null }
    LogonServer      = if ($env:LOGONSERVER) { $env:LOGONSERVER } else { $null }
    Errors           = @()
  }

  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($null -ne $cs.PartOfDomain) { $ctx.PartOfDomain = [bool]$cs.PartOfDomain }
    if ($cs.Domain) { $ctx.Domain = $cs.Domain.Trim() }
    if ($cs.Domain) { $ctx.DomainCandidates += $cs.Domain.Trim() }
  } catch {
    $ctx.Errors += ("ComputerSystemError : {0}" -f $_)
  }

  if ($ctx.UserDnsDomain) { $ctx.DomainCandidates += $ctx.UserDnsDomain }

  $domainSet = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($candidate in $ctx.DomainCandidates) {
    $normalized = Normalize-DomainName $candidate
    if ($normalized) { $null = $domainSet.Add($normalized) }
  }
  $ctx.DomainCandidates = @($domainSet) | Sort-Object -Unique

  if ($ctx.PartOfDomain) {
    try {
      $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
      if ($domainObj) {
        if ($domainObj.Name) { $ctx.DomainDnsName = $domainObj.Name.Trim() }
        if ($domainObj.Forest -and $domainObj.Forest.Name) {
          $ctx.ForestCandidates += $domainObj.Forest.Name.Trim()
        }
      }
    } catch {
      $ctx.Errors += ("GetComputerDomainError : {0}" -f $_)
    }

    try {
      $forestObj = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
      if ($forestObj -and $forestObj.Name) { $ctx.ForestCandidates += $forestObj.Name.Trim() }
    } catch {
      $ctx.Errors += ("GetCurrentForestError : {0}" -f $_)
    }
  }

  $forestSet = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($candidate in $ctx.ForestCandidates + $ctx.DomainCandidates) {
    $normalizedForest = Normalize-DomainName $candidate
    if ($normalizedForest) { $null = $forestSet.Add($normalizedForest) }
  }
  $ctx.ForestCandidates = @($forestSet) | Sort-Object -Unique

  if (-not $ctx.DomainDnsName -and $ctx.DomainCandidates.Count -gt 0) {
    $ctx.DomainDnsName = $ctx.DomainCandidates[0]
  }

  return [pscustomobject]$ctx
}
