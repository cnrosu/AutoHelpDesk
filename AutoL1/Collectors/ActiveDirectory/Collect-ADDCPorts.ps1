. (Join-Path $PSScriptRoot 'Common.ps1')

function Invoke-ADDomainControllerPortTests {
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

  if ($ctx.DomainCandidates -and $ctx.DomainCandidates.Count -gt 0) {
    Write-Output ("DomainCandidates : {0}" -f ($ctx.DomainCandidates -join ', '))
  } else {
    Write-Output "DomainCandidates : (none)"
  }

  $dcSet = [System.Collections.Generic.HashSet[string]]::new()
  $domainList = $ctx.DomainCandidates
  foreach ($domain in $domainList) {
    $dsOutput = nltest /dsgetdc:$domain 2>&1
    foreach ($line in $dsOutput) {
      if ($line -match '^\s*DC:\s*\\(?<dc>[^\s]+)') {
        $dcName = ConvertTo-Fqdn $matches['dc'] $ctx.DomainDnsName
        if ($dcName) { $null = $dcSet.Add($dcName) }
      }
    }
    $dcList = nltest /dclist:$domain 2>&1
    foreach ($line in $dcList) {
      if ($line -match '^\s*(?<name>[A-Za-z0-9\-\.]+)(?:\s*\(.*\))?$') {
        $candidate = $matches['name']
        if ($candidate -and $candidate -notmatch '^(Get|The|List|of|Domain|domain|from|completed|successfully)$') {
          $fqdnCandidate = ConvertTo-Fqdn $candidate $ctx.DomainDnsName
          if ($fqdnCandidate) { $null = $dcSet.Add($fqdnCandidate) }
        }
      }
    }
  }

  $dcListFinal = @($dcSet) | Sort-Object
  if (-not $dcListFinal -or $dcListFinal.Count -eq 0) {
    Write-Output "CandidateDCs : (none)"
    return
  }

  Write-Output ("CandidateDCs : {0}" -f ($dcListFinal -join ', '))
  $testCmd = Get-Command Test-NetConnection -ErrorAction SilentlyContinue
  if (-not $testCmd) {
    Write-Output "Status : Test-NetConnection unavailable"
    return
  }

  $ports = @(88, 389, 445, 135)
  foreach ($dc in $dcListFinal) {
    Write-Output ("PortTestTarget : {0}" -f $dc)
    foreach ($port in $ports) {
      try {
        $result = Test-NetConnection -ComputerName $dc -Port $port -WarningAction SilentlyContinue -ErrorAction Stop
        $tcp = if ($result.TcpTestSucceeded) { $result.TcpTestSucceeded } else { $false }
        $addr = $null
        if ($result.RemoteAddress) {
          if ($result.RemoteAddress -is [System.Net.IPAddress]) {
            $addr = $result.RemoteAddress.IPAddressToString
          } else {
            $addr = [string]$result.RemoteAddress
          }
        }
        Write-Output ("PortResult : {0}| Port={1} | Success={2} | RemoteAddress={3}" -f $dc, $port, $tcp, (if ($addr) { $addr } else { '' }))
      } catch {
        Write-Output ("PortResult : {0}| Port={1} | Success=Error | Error={2}" -f $dc, $port, $_)
      }
    }
    Write-Output ""
  }
}
