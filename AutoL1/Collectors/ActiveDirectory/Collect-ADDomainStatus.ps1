. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ADDomainStatusCollection {
  param(
    [pscustomobject]$Context
  )

  $ctx = if ($PSBoundParameters.ContainsKey('Context') -and $Context) { $Context } else { Get-ADCollectorContext }

  Write-Output ("Timestamp : {0:o}" -f (Get-Date))
  Write-Output ("ComputerName : {0}" -f $ctx.ComputerName)
  $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
  Write-Output ("PartOfDomain : {0}" -f $partText)
  if ($ctx.Domain) { Write-Output ("Domain : {0}" -f $ctx.Domain) }
  if ($ctx.DomainDnsName) { Write-Output ("DomainDnsName : {0}" -f $ctx.DomainDnsName) }
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
  if ($ctx.UserDnsDomain) { Write-Output ("USERDNSDOMAIN : {0}" -f $ctx.UserDnsDomain) }
  if ($ctx.UserDomain) { Write-Output ("USERDOMAIN : {0}" -f $ctx.UserDomain) }
  if ($ctx.LogonServer) { Write-Output ("LOGONSERVER : {0}" -f $ctx.LogonServer) }
  if ($ctx.Errors -and $ctx.Errors.Count -gt 0) {
    foreach ($err in $ctx.Errors) { Write-Output $err }
  }
  if ($ctx.PartOfDomain) {
    try {
      $root = [ADSI]'LDAP://RootDSE'
      if ($root) {
        if ($root.defaultNamingContext) { Write-Output ("DefaultNamingContext : {0}" -f $root.defaultNamingContext) }
        if ($root.rootDomainNamingContext) { Write-Output ("RootDomainNamingContext : {0}" -f $root.rootDomainNamingContext) }
        if ($root.configurationNamingContext) { Write-Output ("ConfigurationNamingContext : {0}" -f $root.configurationNamingContext) }
      }
    } catch {
      Write-Output ("RootDSEError : {0}" -f $_)
    }
  }
}
