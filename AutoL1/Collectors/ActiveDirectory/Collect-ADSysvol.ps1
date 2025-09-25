. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ADSysvolCollection {
  param(
    [pscustomobject]$Context
  )

  $ctx = if ($PSBoundParameters.ContainsKey('Context') -and $Context) { $Context } else { Get-ADCollectorContext }

  Write-Output ("Timestamp : {0:o}" -f (Get-Date))
  $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
  Write-Output ("PartOfDomain : {0}" -f $partText)
  if ($ctx.PartOfDomain -ne $true) {
    Write-Output "Status : Skipped (NotDomainJoined)"
    return
  }

  $domainFqdn = $null
  if ($ctx.DomainDnsName) { $domainFqdn = $ctx.DomainDnsName }
  elseif ($ctx.UserDnsDomain) { $domainFqdn = $ctx.UserDnsDomain }
  elseif ($ctx.Domain) { $domainFqdn = $ctx.Domain }

  if (-not $domainFqdn) {
    Write-Output "DomainFqdn : (unknown)"
    return
  }

  Write-Output ("DomainFqdn : {0}" -f $domainFqdn)
  $paths = @(
    @{ Label = 'SYSVOL'; Path = "\\$domainFqdn\SYSVOL" },
    @{ Label = 'NETLOGON'; Path = "\\$domainFqdn\NETLOGON" }
  )

  foreach ($entry in $paths) {
    $label = $entry.Label
    $path = $entry.Path
    Write-Output ("SharePath : {0} | Path={1}" -f $label, $path)
    try {
      $exists = Test-Path -Path $path -PathType Container -ErrorAction Stop
      Write-Output ("ShareExists : {0} | Path={1} | Exists={2}" -f $label, $path, $exists)
      if ($exists) {
        try {
          $items = Get-ChildItem -Path $path -ErrorAction Stop | Select-Object -First 10
          if ($items) {
            $names = $items | ForEach-Object { $_.Name }
            Write-Output ("ShareSample : {0} | Items={1}" -f $label, ($names -join ', '))
          } else {
            Write-Output ("ShareSample : {0} | Items=(empty)" -f $label)
          }
        } catch {
          Write-Output ("ShareSampleError : {0} | Error={1}" -f $label, $_)
        }
      }
    } catch {
      Write-Output ("ShareExists : {0} | Path={1} | Exists=Error" -f $label, $path)
      Write-Output ("ShareError : {0} | Error={1}" -f $label, $_)
    }
    Write-Output ""
  }
}
