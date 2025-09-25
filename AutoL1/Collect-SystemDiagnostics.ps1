<#
Collect-SystemDiagnostics.ps1
Collect a broad snapshot of a Windows machine and build a simple HTML report.
Run as Administrator.
#>

[CmdletBinding()]
param(
  [string]$OutRoot = "$env:USERPROFILE\Desktop\DiagReports",
  [switch]$NoHtml  # if set, skip HTML generation
)

# Ensure Admin
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script elevated (Run as Administrator)."
    exit 1
  }
}
Assert-Admin

$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$reportDir = Join-Path -Path $OutRoot -ChildPath $timestamp
New-Item -Path $reportDir -ItemType Directory -Force | Out-Null

$overallTimer = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "Starting diagnostics collection..."
Write-Host "Output folder: $reportDir"

# Simple helper to run a command and write output
function Save-Output {
  param(
    [Parameter(Mandatory)] [string]$Name,
    [Parameter(Mandatory)] [scriptblock]$Action
  )

  $file = Join-Path $reportDir ("$Name.txt")
  $sep = "`n===== $Name : $(Get-Date) =====`n"
  Add-Content -Path $file -Value $sep
  try {
    & $Action *>&1 | Out-File -FilePath $file -Encoding UTF8 -Append
  } catch {
    "ERROR running $Name : $_" | Out-File -FilePath $file -Append
    Write-Warning "Encountered an error while collecting $Name. Review $file for details."
  }
  return $file
}

$script:DomainContextCache = $null
$script:AdCandidateCache = $null

function Get-DomainContext {
  if ($script:DomainContextCache) { return $script:DomainContextCache }

  $errors = New-Object System.Collections.Generic.List[string]
  $context = [ordered]@{
    Timestamp        = (Get-Date)
    ComputerName     = $env:COMPUTERNAME
    PartOfDomain     = $null
    Domain           = $null
    Forest           = $null
    Workgroup        = $null
    UserDnsDomain    = $env:USERDNSDOMAIN
    PrimaryDnsSuffix = $null
    DomainRole       = $null
    SiteName         = $null
    Errors           = @()
  }

  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($null -ne $cs.PartOfDomain) { $context.PartOfDomain = [bool]$cs.PartOfDomain }
    if ($cs.Domain) {
      $context.Domain = $cs.Domain.Trim()
      if ($context.PartOfDomain -ne $true -and $context.Domain -and $context.Domain.ToUpperInvariant() -ne 'WORKGROUP') {
        $context.PartOfDomain = $true
      }
    }
    if ($cs.DomainRole -ne $null) { $context.DomainRole = [int]$cs.DomainRole }
  } catch {
    $errors.Add("Win32_ComputerSystem query failed: $_") | Out-Null
  }

  if (-not $context.Domain) {
    $envDomain = $env:USERDOMAIN
    if ($envDomain) { $context.Domain = $envDomain.Trim() }
  }

  if ($context.Domain -and $context.Domain.ToUpperInvariant() -eq 'WORKGROUP') {
    $context.Workgroup = $context.Domain
    $context.PartOfDomain = $false
    $context.Domain = $null
  }

  try {
    $si = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ($si.Primary) {
      # no-op, Primary property not widely populated
    }
    if ($si.CSName) { $null = $si.CSName }
    if ($si.PSComputerName) { $null = $si.PSComputerName }
    if ($si.PSObject.Properties['Primary']) { $null = $si.PSObject.Properties['Primary'] }
    if ($si.PSObject.Properties['Primary']) { $null = $si.PSObject.Properties['Primary'].Value }
    if ($si.CSName) { $null = $si.CSName }
  } catch {}

  try {
    $osInfo = systeminfo 2>$null
    if ($osInfo) {
      foreach ($line in $osInfo) {
        if ($null -eq $context.PrimaryDnsSuffix) {
          if ($line -match '^(?i)\s*Primary Dns Suffix\s*:\s*(.+)$') {
            $suffix = $matches[1].Trim()
            if ($suffix) { $context.PrimaryDnsSuffix = $suffix }
          }
        }
        if ($null -eq $context.Domain -and $line -match '^(?i)\s*Domain\s*:\s*(.+)$') {
          $domainValue = $matches[1].Trim()
          if ($domainValue -and $domainValue.ToUpperInvariant() -ne 'WORKGROUP') {
            $context.Domain = $domainValue
          } elseif ($domainValue) {
            $context.Workgroup = $domainValue
            $context.PartOfDomain = $false
          }
        }
      }
    }
  } catch {
    $errors.Add("systeminfo query failed: $_") | Out-Null
  }

  if (-not $context.Forest -and $context.Domain) {
    try {
      Add-Type -AssemblyName System.DirectoryServices.ActiveDirectory -ErrorAction Stop
      $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
      if ($domainObj -and $domainObj.Forest -and $domainObj.Forest.Name) {
        $context.Forest = $domainObj.Forest.Name
      }
      if ($domainObj -and $domainObj.Name) {
        $context.Domain = $domainObj.Name
      }
    } catch {
      $errors.Add("Forest discovery failed: $_") | Out-Null
    }
  }

  if (-not $context.Forest -and $context.PrimaryDnsSuffix) { $context.Forest = $context.PrimaryDnsSuffix }
  if (-not $context.Forest -and $context.Domain) { $context.Forest = $context.Domain }

  if ($context.PartOfDomain -eq $true) {
    try {
      $siteOutput = nltest /dsgetsite 2>&1
      if ($LASTEXITCODE -eq 0 -and $siteOutput) {
        $siteLine = ($siteOutput | Select-Object -First 1)
        if ($siteLine -match '^(?i)The site name is\s*:\s*(.+)$') {
          $context.SiteName = $matches[1].Trim()
        } elseif ($siteLine -match '^(?i)Site Name:\s*(.+)$') {
          $context.SiteName = $matches[1].Trim()
        } elseif ($siteLine -and -not ($siteLine -match '^(?i)The command completed successfully')) {
          $context.SiteName = $siteLine.Trim()
        }
      }
    } catch {
      $errors.Add("nltest /dsgetsite failed: $_") | Out-Null
    }
  }

  if ($errors.Count -gt 0) { $context.Errors = $errors }

  $script:DomainContextCache = [pscustomobject]$context
  return $script:DomainContextCache
}

function Reset-AdDiscoveryCache {
  $script:AdCandidateCache = $null
}

function Get-DomainControllerDiscovery {
  if ($script:AdCandidateCache) { return $script:AdCandidateCache }

  $context = Get-DomainContext
  $result = [ordered]@{
    DomainJoined = $context.PartOfDomain
    Domain       = $context.Domain
    Forest       = $context.Forest
    Commands     = @()
    SrvLookups   = @()
    Candidates   = @()
    Notes        = @()
  }

  $result.Commands = New-Object System.Collections.Generic.List[pscustomobject]
  $result.SrvLookups = New-Object System.Collections.Generic.List[pscustomobject]
  $result.Candidates = New-Object System.Collections.Generic.List[pscustomobject]
  $notes = New-Object System.Collections.Generic.List[string]

  if ($context.PartOfDomain -ne $true -or -not $context.Domain) {
    if ($context.PartOfDomain -ne $true) { $notes.Add('Device not domain joined.') | Out-Null }
    $result.Notes = $notes
    $script:AdCandidateCache = [pscustomobject]$result
    return $script:AdCandidateCache
  }

  $domainName = $context.Domain
  $forestName = if ($context.Forest) { $context.Forest } elseif ($context.Domain) { $context.Domain } else { $null }

  $candidateTable = @{}

  $addCandidate = {
    param([string]$Host,[string]$Source)
    if (-not $Host) { return }
    $trimmed = $Host.Trim()
    if (-not $trimmed) { return }
    $trimmed = $trimmed.TrimStart('\')
    if (-not $trimmed) { return }
    $key = $trimmed.ToLowerInvariant()
    if (-not $candidateTable.ContainsKey($key)) {
      $candidateTable[$key] = @{
        Host    = $trimmed
        Sources = New-Object System.Collections.Generic.List[string]
      }
    }
    if ($Source -and -not ($candidateTable[$key].Sources -contains $Source)) {
      $null = $candidateTable[$key].Sources.Add($Source)
    }
  }

  $nltestCommands = @()
  if ($domainName) {
    $nltestCommands += @{
      Name = "nltest /dsgetdc:$domainName"
      Arguments = @("/dsgetdc:$domainName")
    }
    $nltestCommands += @{
      Name = "nltest /dclist:$domainName"
      Arguments = @("/dclist:$domainName")
    }
  }

  foreach ($cmd in $nltestCommands) {
    $output = @()
    $exitCode = $null
    try {
      $output = (nltest @($cmd.Arguments) 2>&1)
      $exitCode = $LASTEXITCODE
    } catch {
      $output = @("Command threw exception: $_")
      $exitCode = $LASTEXITCODE
    }

    $entry = [ordered]@{
      Name     = $cmd.Name
      ExitCode = if ($exitCode -ne $null) { [int]$exitCode } else { $null }
      Output   = @($output)
    }
    $result.Commands.Add([pscustomobject]$entry)

    foreach ($line in $output) {
      if (-not $line) { continue }
      if ($line -match '\\\\(?<host>[A-Za-z0-9_.-]+)') {
        &$addCandidate $matches['host'] $cmd.Name
      }
      if ($line -match '(?i)Address:\s*\\\\(?<addr>[A-Za-z0-9_.-]+)') {
        &$addCandidate $matches['addr'] $cmd.Name
      }
      if ($line -match '(?i)Name: (?<name>[A-Za-z0-9_.-]+)') {
        &$addCandidate $matches['name'] $cmd.Name
      }
    }
  }

  $resolveCmd = Get-Command Resolve-DnsName -ErrorAction SilentlyContinue
  if (-not $resolveCmd) {
    $notes.Add('Resolve-DnsName cmdlet unavailable.') | Out-Null
  }

  $srvQueries = New-Object System.Collections.Generic.List[pscustomobject]
  if ($forestName) {
    $srvQueries.Add([pscustomobject]@{ Query = "_ldap._tcp.dc._msdcs.$forestName"; Label = '_ldap_dc_msdc' }) | Out-Null
  }
  if ($domainName) {
    $srvQueries.Add([pscustomobject]@{ Query = "_kerberos._tcp.$domainName"; Label = '_kerberos_tcp' }) | Out-Null
  }

  foreach ($query in $srvQueries) {
    $records = @()
    $error = $null
    $succeeded = $null
    if ($resolveCmd) {
      try {
        $records = Resolve-DnsName -Name $query.Query -Type SRV -ErrorAction Stop
        $succeeded = $true
      } catch {
        $error = $_.ToString()
        $succeeded = $false
        $records = @()
      }
    }

    $recordSummaries = @()
    foreach ($rec in $records) {
      if ($rec.NameTarget) {
        $recordSummaries += [ordered]@{
          Target   = $rec.NameTarget
          Priority = $rec.Priority
          Weight   = $rec.Weight
          Port     = $rec.Port
        }
        &$addCandidate $rec.NameTarget "SRV:$($query.Query)"
      }
    }

    $result.SrvLookups.Add([pscustomobject]@{
      Query     = $query.Query
      Succeeded = $succeeded
      Records   = $recordSummaries
      Error     = $error
    }) | Out-Null
  }

  foreach ($entry in $candidateTable.GetEnumerator()) {
    $host = $entry.Value.Host
    $sources = [string[]]$entry.Value.Sources
    $ipv4 = @()
    $ipv6 = @()
    if ($resolveCmd) {
      try {
        $aRecords = Resolve-DnsName -Name $host -Type A -ErrorAction Stop
        $ipv4 = @($aRecords | ForEach-Object { $_.IPAddress })
      } catch {}
      try {
        $aaaaRecords = Resolve-DnsName -Name $host -Type AAAA -ErrorAction Stop
        $ipv6 = @($aaaaRecords | ForEach-Object { $_.IPAddress })
      } catch {}
    }
    $result.Candidates.Add([pscustomobject]@{
      Host    = $host
      Sources = $sources
      IPv4    = @($ipv4)
      IPv6    = @($ipv6)
    }) | Out-Null
  }

  $finalNotes = if ($notes.Count -gt 0) { @($notes) } else { @() }

  $script:AdCandidateCache = [pscustomobject]@{
    Timestamp    = (Get-Date)
    DomainJoined = $result.DomainJoined
    Domain       = $result.Domain
    Forest       = $result.Forest
    Commands     = @($result.Commands)
    SrvLookups   = @($result.SrvLookups)
    Candidates   = @($result.Candidates)
    Notes        = $finalNotes
  }
  return $script:AdCandidateCache
}

function Test-TcpPortConnection {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][int]$Port,
    [int]$TimeoutMs = 2000
  )

  $client = $null
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
      $client.Close()
      return [pscustomobject]@{
        Success = $false
        Error   = 'Timeout'
      }
    }
    $client.EndConnect($async)
    $client.Close()
    return [pscustomobject]@{
      Success = $true
      Error   = $null
    }
  } catch {
    if ($client) { $client.Close() }
    return [pscustomobject]@{
      Success = $false
      Error   = $_.Exception.Message
    }
  }
}

$capturePlan = @(
  @{ Name = "ipconfig_all"; Description = "Detailed IP configuration (ipconfig /all)"; Action = { ipconfig /all } },
  @{ Name = "route_print"; Description = "Routing table (route print)"; Action = { route print } },
  @{ Name = "netstat_ano"; Description = "Active connections and ports (netstat -ano)"; Action = { netstat -ano } },
  @{ Name = "arp_table"; Description = "ARP cache entries (arp -a)"; Action = { arp -a } },
  @{ Name = "nslookup_google"; Description = "DNS resolution test for google.com"; Action = { nslookup google.com } },
  @{ Name = "tracert_google"; Description = "Traceroute to 8.8.8.8"; Action = { tracert -d -h 10 8.8.8.8 } },
  @{ Name = "ping_google"; Description = "Ping test to 8.8.8.8"; Action = { ping -n 4 8.8.8.8 } },
  @{ Name = "TestNetConnection_Outlook443"; Description = "Test HTTPS connectivity to outlook.office365.com"; Action = {
      $testNetCmd = Get-Command Test-NetConnection -ErrorAction SilentlyContinue
      if (-not $testNetCmd) {
        "Test-NetConnection cmdlet not available on this system."
      } else {
        Test-NetConnection outlook.office365.com -Port 443 -WarningAction SilentlyContinue |
          Format-List * |
          Out-String
      }
    } },
  @{ Name = "Outlook_OST"; Description = "Outlook OST cache inventory"; Action = {
      $ostRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\\Outlook'
      if (-not (Test-Path $ostRoot)) {
        "Outlook OST root not found: $ostRoot"
      } else {
        $ostFiles = Get-ChildItem -Path $ostRoot -Filter *.ost -Recurse -ErrorAction SilentlyContinue
        if (-not $ostFiles) {
          "No OST files found under $ostRoot"
        } else {
          $ostFiles |
            Sort-Object Length -Descending |
            Select-Object FullName, Length, LastWriteTime |
            Format-List * |
            Out-String
        }
      }
    } },
  @{ Name = "Autodiscover_DNS"; Description = "Autodiscover DNS lookups"; Action = {
      $domains = @()
      if ($env:USERDNSDOMAIN) { $domains += $env:USERDNSDOMAIN }
      try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.Domain) { $domains += $cs.Domain }
      } catch {}

      $ostRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\\Outlook'
      if (Test-Path $ostRoot) {
        Get-ChildItem -Path $ostRoot -Filter *.ost -Recurse -ErrorAction SilentlyContinue |
          ForEach-Object {
            $base = $_.BaseName
            if ($base -match '@(?<domain>[A-Za-z0-9\.-]+\.[A-Za-z]{2,})') {
              $domains += $matches['domain']
            }
          }
      }

      $domains = $domains |
        Where-Object { $_ } |
        ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Where-Object { $_ } |
        Sort-Object -Unique

      if (-not $domains -or $domains.Count -eq 0) {
        "No domain candidates identified for autodiscover lookup."
      } else {
        $resolveCmd = Get-Command Resolve-DnsName -ErrorAction SilentlyContinue
        if (-not $resolveCmd) {
          "Resolve-DnsName cmdlet not available."
        } else {
          foreach ($domain in $domains) {
            Write-Output ("### Domain: {0}" -f $domain)
            $fqdn = "autodiscover.$domain"
            try {
              $results = Resolve-DnsName -Name $fqdn -Type CNAME -ErrorAction Stop |
                Select-Object Name, Type, NameHost |
                Format-Table -AutoSize |
                Out-String -Width 200
              if ($results) {
                Write-Output ($results.TrimEnd())
              } else {
                Write-Output "No CNAME records returned."
              }
            } catch {
              Write-Output ("Resolve-DnsName failed for {0}: {1}" -f $fqdn, $_)
            }
            Write-Output ""
          }
        }
      }
    } },
  @{ Name = "Outlook_SCP"; Description = "Autodiscover SCP search (Active Directory)"; Action = {
      $domainJoined = $null
      $domainQueryError = $null
      try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($null -ne $cs.PartOfDomain) {
          $domainJoined = [bool]$cs.PartOfDomain
        }
      } catch {
        $domainQueryError = $_
      }

      if ($domainJoined -eq $true) {
        Write-Output "PartOfDomain : True"
      } elseif ($domainJoined -eq $false) {
        Write-Output "PartOfDomain : False"
        Write-Output "Status : Skipped (NotDomainJoined)"
        return
      } else {
        Write-Output "PartOfDomain : Unknown"
        if ($domainQueryError) {
          Write-Output ("PartOfDomainError : {0}" -f $domainQueryError)
        }
      }

      try {
        $root = [ADSI]"LDAP://RootDSE"
        $configNc = $root.configurationNamingContext
        if (-not $configNc) {
          Write-Output "Status : QueryFailed (ConfigurationNamingContextUnavailable)"
          return
        }

        Write-Output ("ConfigurationNamingContext : {0}" -f $configNc)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]("LDAP://$configNc")
        $searcher.Filter = "(&(objectClass=serviceConnectionPoint)(keywords=77378F46-2C66-4AA9-A6A6-3E7A48B19596))"
        $searcher.PageSize = 1000
        [void]$searcher.PropertiesToLoad.Add('name')
        [void]$searcher.PropertiesToLoad.Add('serviceBindingInformation')
        [void]$searcher.PropertiesToLoad.Add('keywords')
        [void]$searcher.PropertiesToLoad.Add('distinguishedName')
        [void]$searcher.PropertiesToLoad.Add('whenChanged')
        $results = $searcher.FindAll()
        if (-not $results -or $results.Count -eq 0) {
          Write-Output "Status : NoResults"
        } else {
          Write-Output ("Status : Found {0} result(s)" -f $results.Count)
          foreach ($result in $results) {
            $name = ($result.Properties['name'] | Select-Object -First 1)
            $binding = $result.Properties['servicebindinginformation']
            $keywords = $result.Properties['keywords']
            $dn = ($result.Properties['distinguishedname'] | Select-Object -First 1)
            $changed = ($result.Properties['whenchanged'] | Select-Object -First 1)
            if ($name) { Write-Output ("Name : {0}" -f $name) }
            if ($dn) { Write-Output ("DistinguishedName : {0}" -f $dn) }
            if ($binding) { Write-Output ("ServiceBindingInformation : {0}" -f ($binding -join '; ')) }
            if ($keywords) { Write-Output ("Keywords : {0}" -f ($keywords -join '; ')) }
            if ($changed) { Write-Output ("WhenChanged : {0}" -f $changed) }
            Write-Output ""
          }
        }
      } catch {
        Write-Output "Status : QueryFailed (Exception)"
        Write-Output ("Error : {0}" -f $_)
      }
    } },
  @{ Name = "AD_DomainStatus"; Description = "Active Directory domain status"; Action = {
      $context = Get-DomainContext
      if ($context) {
        ($context | ConvertTo-Json -Depth 6)
      } else {
        "Domain context not captured."
      }
    } },
  @{ Name = "AD_DCDiscovery"; Description = "Domain controller discovery"; Action = {
      Reset-AdDiscoveryCache
      $discovery = Get-DomainControllerDiscovery
      if ($discovery) {
        ($discovery | ConvertTo-Json -Depth 6)
      } else {
        "Discovery unavailable."
      }
    } },
  @{ Name = "AD_DCReachability"; Description = "Domain controller port reachability"; Action = {
      $discovery = Get-DomainControllerDiscovery
      if (-not $discovery -or $discovery.DomainJoined -ne $true) {
        (@{
            Status  = 'Skipped'
            Reason  = 'NotDomainJoined'
            Tested  = @()
            Ports   = @(88,389,445,135)
            Notes   = if ($discovery -and $discovery.Notes) { $discovery.Notes } else { @() }
          } | ConvertTo-Json -Depth 6)
        return
      }

      $candidates = $discovery.Candidates
      if (-not $candidates -or $candidates.Count -eq 0) {
        (@{
            Status = 'NoCandidates'
            Ports  = @(88,389,445,135)
            Notes  = if ($discovery.Notes) { $discovery.Notes } else { @('No domain controllers discovered.') }
          } | ConvertTo-Json -Depth 6)
        return
      }

      $portsToTest = @(88,389,445,135)
      $targets = New-Object System.Collections.Generic.List[pscustomobject]

      foreach ($candidate in $candidates) {
        $ports = New-Object System.Collections.Generic.List[pscustomobject]
        $targetName = $candidate.Host
        $sources = if ($candidate.Sources) { [string[]]$candidate.Sources } else { @() }
        $ipv4 = if ($candidate.IPv4) { [string[]]$candidate.IPv4 } else { @() }
        $ipv6 = if ($candidate.IPv6) { [string[]]$candidate.IPv6 } else { @() }

        foreach ($port in $portsToTest) {
          $timer = [System.Diagnostics.Stopwatch]::StartNew()
          $probe = Test-TcpPortConnection -ComputerName $targetName -Port $port -TimeoutMs 2500
          $timer.Stop()
          $ports.Add([pscustomobject]@{
            Port       = $port
            Success    = [bool]$probe.Success
            Error      = $probe.Error
            DurationMs = [math]::Round($timer.Elapsed.TotalMilliseconds,0)
          }) | Out-Null
        }

        $targets.Add([pscustomobject]@{
          Target  = $targetName
          Sources = $sources
          IPv4    = $ipv4
          IPv6    = $ipv6
          Ports   = @($ports)
        }) | Out-Null
      }

      (@{
          Timestamp = (Get-Date)
          Status    = 'Completed'
          Ports     = $portsToTest
          Targets   = @($targets)
        } | ConvertTo-Json -Depth 6)
    } },
  @{ Name = "AD_SysvolAccess"; Description = "SYSVOL/NETLOGON accessibility"; Action = {
      $context = Get-DomainContext
      if ($context.PartOfDomain -ne $true -or -not $context.Domain) {
        (@{
            Status = 'Skipped'
            Reason = 'NotDomainJoined'
          } | ConvertTo-Json -Depth 4)
        return
      }

      $sysvolPath = '\\{0}\SYSVOL' -f $context.Domain
      $netlogonPath = '\\{0}\NETLOGON' -f $context.Domain
      $paths = @($sysvolPath, $netlogonPath)
      $results = New-Object System.Collections.Generic.List[pscustomobject]

      foreach ($path in $paths) {
        $entry = [ordered]@{
          Path    = $path
          Exists  = $null
          Success = $false
          Items   = @()
          Error   = $null
        }

        try {
          if (Test-Path -Path $path) {
            $entry.Exists = $true
            try {
              $items = Get-ChildItem -Path $path -ErrorAction Stop | Select-Object -First 5
              if ($items) {
                $entry.Success = $true
                $entry.Items = ($items | Select-Object -Property Name, FullName)
              } else {
                $entry.Success = $true
                $entry.Items = @()
              }
            } catch {
              $entry.Error = $_.ToString()
            }
          } else {
            $entry.Exists = $false
          }
        } catch {
          $entry.Error = $_.ToString()
        }

        $results.Add([pscustomobject]$entry) | Out-Null
      }

      (@{
          Timestamp = (Get-Date)
          Results   = @($results)
        } | ConvertTo-Json -Depth 6)
    } },
  @{ Name = "AD_TimeStatus"; Description = "Windows Time status"; Action = {
      $output = New-Object System.Collections.Generic.List[string]
      $output.Add('### w32tm /query /status') | Out-Null
      try {
        $status = w32tm /query /status 2>&1
        if ($status) { $output.AddRange($status) }
      } catch {
        $output.Add("Error: $_") | Out-Null
      }
      $output.Add('') | Out-Null
      $output.Add('### w32tm /query /peers') | Out-Null
      try {
        $peers = w32tm /query /peers 2>&1
        if ($peers) { $output.AddRange($peers) }
      } catch {
        $output.Add("PeersError: $_") | Out-Null
      }
      ($output -join "`n")
    } },
  @{ Name = "AD_KerberosTickets"; Description = "Kerberos ticket cache"; Action = {
      try {
        klist 2>&1
      } catch {
        "klist failed: $_"
      }
    } },
  @{ Name = "AD_SecureChannel"; Description = "Secure channel verification"; Action = {
      $context = Get-DomainContext
      if ($context.PartOfDomain -ne $true -or -not $context.Domain) {
        "Status : Skipped (NotDomainJoined)"
        return
      }

      Write-Output '### Test-ComputerSecureChannel'
      try {
        $result = Test-ComputerSecureChannel -ErrorAction Stop
        Write-Output ("Result : {0}" -f $result)
      } catch {
        Write-Output ("Result : Error")
        Write-Output ("Error : {0}" -f $_)
      }

      Write-Output ''
      Write-Output ("### nltest /sc_query:{0}" -f $context.Domain)
      try {
        nltest /sc_query:$($context.Domain) 2>&1
      } catch {
        "Command failed: $_"
      }
    } },
  @{ Name = "AD_GPOResult"; Description = "Group Policy result (computer)"; Action = {
      $context = Get-DomainContext
      if ($context.PartOfDomain -ne $true) {
        "Status : Skipped (NotDomainJoined)"
        return
      }
      try {
        gpresult /R /SCOPE COMPUTER /V 2>&1
      } catch {
        "gpresult failed: $_"
      }
    } },
  @{ Name = "AD_GPOEvents"; Description = "Recent GPO error events"; Action = {
      $context = Get-DomainContext
      if ($context.PartOfDomain -ne $true) {
        "Status : Skipped (NotDomainJoined)"
        return
      }
      $query = "*[System[(EventID=1058 or EventID=1030) and TimeCreated[timediff(@SystemTime) <= 259200000]]]"
      try {
        wevtutil qe System /q:$query /c:100 /f:text /rd:true
      } catch {
        "wevtutil failed: $_"
      }
    } },
  @{ Name = "AD_DomainTrusts"; Description = "Domain trusts overview"; Action = {
      $context = Get-DomainContext
      if ($context.PartOfDomain -ne $true -or -not $context.Domain) {
        "Status : Skipped (NotDomainJoined)"
        return
      }
      try {
        nltest /domain_trusts 2>&1
      } catch {
        "nltest /domain_trusts failed: $_"
      }
    } },
  @{ Name = "systeminfo"; Description = "General system information"; Action = { systeminfo } },
  @{ Name = "OS_CIM"; Description = "Operating system CIM inventory"; Action = { Get-CimInstance Win32_OperatingSystem | Format-List * } },
  @{ Name = "ComputerInfo"; Description = "ComputerInfo snapshot"; Action = { Get-ComputerInfo | Select-Object CsName, WindowsVersion, WindowsBuildLabEx, OsName, OsArchitecture, WindowsProductName, OsHardwareAbstractionLayer, Bios* | Format-List * } },
  @{ Name = "Power_Settings"; Description = "Power configuration (Fast Startup)"; Action = {
      Write-Output "Source : HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power"
      try {
        $powerKey = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -ErrorAction Stop
        if ($powerKey) {
          $hiberProperty = $powerKey.PSObject.Properties['HiberbootEnabled']
          if ($hiberProperty) {
            Write-Output ("HiberbootEnabled : {0}" -f $hiberProperty.Value)
          } else {
            Write-Output "HiberbootEnabled : (value not present)"
          }
        } else {
          Write-Output "Failed to read power key (no data returned)."
        }
      } catch {
        Write-Output ("Failed to query HiberbootEnabled : {0}" -f $_)
      }

      Write-Output ""
      $powercfgCmd = Get-Command powercfg -ErrorAction SilentlyContinue
      if ($powercfgCmd) {
        try {
          powercfg /a
        } catch {
          Write-Output ("powercfg /a failed: {0}" -f $_)
        }
      } else {
        Write-Output "powercfg.exe not available."
      }
    } },
  @{ Name = "NetworkAdapterConfigs"; Description = "Network adapter configuration details"; Action = { Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object Description,Index,MACAddress,IPAddress,DefaultIPGateway,DHCPEnabled,DHCPServer,DnsServerSearchOrder | Format-List * } },
  @{ Name = "NetIPAddresses"; Description = "Current IP assignments (Get-NetIPAddress)"; Action = { try { Get-NetIPAddress -ErrorAction Stop | Format-List * } catch { "Get-NetIPAddress missing or failed: $_" } } },
  @{ Name = "NetAdapters"; Description = "Network adapter status"; Action = { try { Get-NetAdapter -ErrorAction Stop | Format-List * } catch { Get-CimInstance Win32_NetworkAdapter | Select-Object Name,NetConnectionStatus,MACAddress,Speed | Format-List * } } },
  @{ Name = "WinHttpProxy"; Description = "WinHTTP proxy configuration"; Action = { netsh winhttp show proxy } },
  @{ Name = "Disk_Drives"; Description = "Physical disk inventory (wmic diskdrive)"; Action = { wmic diskdrive get model,serialNumber,status,size } },
  @{ Name = "Volumes"; Description = "Volume overview (Get-Volume)"; Action = { Get-Volume | Format-Table -AutoSize } },
  @{ Name = "Disks"; Description = "Disk layout (Get-Disk)"; Action = { Get-Disk | Format-List * } },
  @{ Name = "Hotfixes"; Description = "Recent hotfixes"; Action = { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 | Format-List * } },
  @{ Name = "Programs_Reg"; Description = "Installed programs (64-bit registry)"; Action = { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion,Publisher,InstallDate | Format-Table -AutoSize } },
  @{ Name = "Programs_Reg_32"; Description = "Installed programs (32-bit registry)"; Action = { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion,Publisher,InstallDate | Format-Table -AutoSize } },
  @{ Name = "Services"; Description = "Service state overview"; Action = {
      $services = $null
      try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
      } catch {
        try {
          $services = Get-WmiObject Win32_Service -ErrorAction Stop
        } catch {
          Write-Output ("Failed to query services: {0}" -f $_)
          return
        }
      }

      if (-not $services) {
        Write-Output "No services returned."
        return
      }

      $serviceList = @($services | Sort-Object Name)
      Write-Output "Name`tStatus`tStartType`tDisplayName"
      Write-Output "----`t------`t---------`t-----------"
      foreach ($svc in $serviceList) {
        if (-not $svc) { continue }

        $nameValue = if ($svc.Name) { $svc.Name.Trim() } else { '' }
        if (-not $nameValue) { continue }

        $stateValue = ''
        if ($svc.PSObject.Properties['State']) { $stateValue = $svc.State }
        elseif ($svc.PSObject.Properties['Status']) { $stateValue = $svc.Status }
        $stateValue = if ($stateValue) { $stateValue.Trim() } else { 'Unknown' }

        $startMode = if ($svc.PSObject.Properties['StartMode']) { [string]$svc.StartMode } else { '' }
        $delayed = $false
        if ($svc.PSObject.Properties['DelayedAutoStart']) {
          try { $delayed = [bool]$svc.DelayedAutoStart } catch { $delayed = $false }
        }

        $startType = 'Unknown'
        if ($startMode) {
          $modeLower = $startMode.Trim().ToLowerInvariant()
          switch ($modeLower) {
            { $_ -like 'auto*' } {
              if ($delayed) {
                $startType = 'Automatic (Delayed Start)'
              } else {
                $startType = 'Automatic'
              }
              break
            }
            'manual' {
              $startType = 'Manual'
              break
            }
            'disabled' {
              $startType = 'Disabled'
              break
            }
            default {
              $startType = $startMode.Trim()
            }
          }
        }

        $displayName = ''
        if ($svc.PSObject.Properties['DisplayName']) {
          $displayName = [string]$svc.DisplayName
        }
        if ($displayName) {
          $displayName = ($displayName -replace "[\t\r\n]+", ' ').Trim()
        }

        Write-Output ("{0}`t{1}`t{2}`t{3}" -f $nameValue, $stateValue, $startType, $displayName)
      }
    } },
  @{ Name = "Processes"; Description = "Running processes (tasklist /v)"; Action = { tasklist /v } },
  @{ Name = "Drivers"; Description = "Driver inventory (driverquery)"; Action = { driverquery /v /fo list } },
  @{ Name = "Event_System_100"; Description = "Latest 100 System event log entries"; Action = { wevtutil qe System /c:100 /f:text /rd:true } },
  @{ Name = "Event_Application_100"; Description = "Latest 100 Application event log entries"; Action = { wevtutil qe Application /c:100 /f:text /rd:true } },
  @{ Name = "Firewall"; Description = "Firewall profile status"; Action = { netsh advfirewall show allprofiles } },
  @{ Name = "FirewallRules"; Description = "Firewall rules overview"; Action = { try { Get-NetFirewallRule | Select-Object DisplayName,Direction,Action,Enabled,Profile | Format-Table -AutoSize } catch { "Get-NetFirewallRule not present" } } },
  @{ Name = "DefenderStatus"; Description = "Microsoft Defender health"; Action = { try { Get-MpComputerStatus | Format-List * } catch { "Get-MpComputerStatus not available or Defender absent" } } },
  @{ Name = "Office_SecurityPolicies"; Description = "Office macro and Protected View policies"; Action = {
      $apps = @('Excel','Word','PowerPoint')
      $hives = @(
        @{ Label = 'HKCU'; Root = 'HKCU:\Software\Microsoft\Office\16.0' },
        @{ Label = 'HKLM'; Root = 'HKLM:\Software\Microsoft\Office\16.0' }
      )

      foreach ($hive in $hives) {
        foreach ($app in $apps) {
          $appPath = Join-Path -Path $hive.Root -ChildPath $app
          $securityPath = Join-Path -Path $appPath -ChildPath 'Security'
          $contextLabel = "{0}\\{1}" -f $hive.Label, $app

          Write-Output ("Context : {0}" -f $contextLabel)
          Write-Output ("Path : {0}" -f $securityPath)

          $blockValue = 'NotConfigured'
          $warningValue = 'NotConfigured'
          $securityProps = $null

          if (Test-Path $securityPath) {
            try {
              $securityProps = Get-ItemProperty -Path $securityPath -ErrorAction Stop
            } catch {
              Write-Output ("SecurityKeyError : {0}" -f $_)
            }
          }

          if ($securityProps) {
            $blockProp = $securityProps.PSObject.Properties['BlockContentExecutionFromInternet']
            if ($blockProp -and $null -ne $blockProp.Value -and $blockProp.Value -ne '') {
              $blockValue = $blockProp.Value
            }

            $warningProp = $securityProps.PSObject.Properties['VBAWarnings']
            if ($warningProp -and $null -ne $warningProp.Value -and $warningProp.Value -ne '') {
              $warningValue = $warningProp.Value
            }
          }

          Write-Output ("BlockContentExecutionFromInternet : {0}" -f $blockValue)
          Write-Output ("VBAWarnings : {0}" -f $warningValue)

          $protectedViewPath = Join-Path -Path $securityPath -ChildPath 'ProtectedView'
          Write-Output ("ProtectedViewPath : {0}" -f $protectedViewPath)

          $pvInternetValue = 'NotConfigured'
          $pvUnsafeValue = 'NotConfigured'
          $protectedViewProps = $null

          if (Test-Path $protectedViewPath) {
            try {
              $protectedViewProps = Get-ItemProperty -Path $protectedViewPath -ErrorAction Stop
            } catch {
              Write-Output ("ProtectedViewError : {0}" -f $_)
            }
          }

          if ($protectedViewProps) {
            $pvInternetProp = $protectedViewProps.PSObject.Properties['DisableInternetFilesInPV']
            if ($pvInternetProp -and $null -ne $pvInternetProp.Value -and $pvInternetProp.Value -ne '') {
              $pvInternetValue = $pvInternetProp.Value
            }

            $pvUnsafeProp = $protectedViewProps.PSObject.Properties['DisableUnsafeLocationsInPV']
            if ($pvUnsafeProp -and $null -ne $pvUnsafeProp.Value -and $pvUnsafeProp.Value -ne '') {
              $pvUnsafeValue = $pvUnsafeProp.Value
            }
          }

          Write-Output ("ProtectedView.DisableInternetFilesInPV : {0}" -f $pvInternetValue)
          Write-Output ("ProtectedView.DisableUnsafeLocationsInPV : {0}" -f $pvUnsafeValue)
          Write-Output ""
        }
      }
    } },
  @{ Name = "BitLockerStatus"; Description = "BitLocker volume status"; Action = {
      $bitlockerCmd = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue
      if (-not $bitlockerCmd) {
        "Get-BitLockerVolume cmdlet not available on this system."
      } else {
        try {
          Get-BitLockerVolume | Format-List *
        } catch {
          "Get-BitLockerVolume failed: $_"
        }
      }
    } },
  @{ Name = "Security_TPM"; Description = "TPM status"; Action = {
      $cmd = Get-Command Get-Tpm -ErrorAction SilentlyContinue
      if (-not $cmd) {
        "Get-Tpm cmdlet not available on this system."
      } else {
        try {
          Get-Tpm | Format-List *
        } catch {
          "Get-Tpm failed: $_"
        }
      }
    } },
  @{ Name = "Security_DeviceGuard"; Description = "Device Guard / VBS status"; Action = {
      try {
        $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $result = [ordered]@{}
        foreach ($name in @('SecurityServicesConfigured','SecurityServicesRunning','RequiredSecurityProperties','AvailableSecurityProperties','CodeIntegrityPolicyEnforcementStatus','UsermodeCodeIntegrityPolicyEnforcementStatus','InstanceIdentifier','VirtualizationBasedSecurityStatus','IsVirtualizationBasedSecurityEnabled')) {
          $prop = $dg.PSObject.Properties[$name]
          if ($prop) {
            $result[$name] = $prop.Value
          }
        }
        ($result | ConvertTo-Json -Depth 5)
      } catch {
        "Get-CimInstance Win32_DeviceGuard failed: $_"
      }
    } },
  @{ Name = "Security_ComputerSystem"; Description = "Computer system security profile"; Action = {
      try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $result = [ordered]@{}
        foreach ($name in @('Name','Manufacturer','Model','SystemFamily','SystemSkuNumber','Domain','DomainRole','PartOfDomain','PCSystemType','PCSystemTypeEx','TotalPhysicalMemory','NumberOfProcessors','NumberOfLogicalProcessors')) {
          $prop = $cs.PSObject.Properties[$name]
          if ($prop) {
            $result[$name] = $prop.Value
          }
        }
        ($result | ConvertTo-Json -Depth 5)
      } catch {
        "Get-CimInstance Win32_ComputerSystem failed: $_"
      }
    } },
  @{ Name = "Security_SystemEnclosure"; Description = "System enclosure / chassis info"; Action = {
      try {
        $entries = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop
        if ($entries -is [System.Array]) {
          $list = @()
          foreach ($item in $entries) {
            $entry = [ordered]@{}
            foreach ($name in @('ChassisTypes','SecurityStatus','SMBIOSAssetTag','SerialNumber','Manufacturer','Version')) {
              $prop = $item.PSObject.Properties[$name]
              if ($prop) {
                $entry[$name] = $prop.Value
              }
            }
            $list += $entry
          }
          ($list | ConvertTo-Json -Depth 5)
        } else {
          $entry = [ordered]@{}
          foreach ($name in @('ChassisTypes','SecurityStatus','SMBIOSAssetTag','SerialNumber','Manufacturer','Version')) {
            $prop = $entries.PSObject.Properties[$name]
            if ($prop) {
              $entry[$name] = $prop.Value
            }
          }
          ($entry | ConvertTo-Json -Depth 5)
        }
      } catch {
        "Get-CimInstance Win32_SystemEnclosure failed: $_"
      }
    } },
  @{ Name = "Security_KernelDMA"; Description = "Kernel DMA protection status"; Action = {
      $target = Join-Path $reportDir 'msinfo32_dma.txt'
      try {
        $arguments = "/report `"$target`" /categories +SystemSummary"
        Start-Process -FilePath msinfo32.exe -ArgumentList $arguments -WindowStyle Hidden -Wait | Out-Null
        if (Test-Path $target) {
          $content = Get-Content -Path $target
          $filtered = $content | Where-Object { $_ -match 'Kernel DMA Protection' -or $_ -match 'Device Encryption Support' -or $_ -match 'Virtualization-based security' }
          if ($filtered) {
            $filtered
          } else {
            $content | Select-Object -First 60
          }
        } else {
          "msinfo32 report file not generated: $target"
        }
      } catch {
        "msinfo32 /report failed: $_"
      }
    } },
  @{ Name = "Security_RDP"; Description = "Remote Desktop configuration"; Action = {
      $output = New-Object System.Collections.Generic.List[string]
      $rootPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
      if (Test-Path $rootPath) {
        $output.Add("Path : $rootPath")
        try {
          $lines = (Get-ItemProperty -Path $rootPath -ErrorAction Stop | Select-Object fDenyTSConnections,AllowTSConnections | Format-List * | Out-String).TrimEnd()
          if ($lines) { $output.AddRange($lines -split "`r?`n") }
        } catch {
          $output.Add("RootError : $_")
        }
      } else {
        $output.Add("PathMissing : $rootPath")
      }
      $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
      if (Test-Path $rdpTcpPath) {
        $output.Add("Path : $rdpTcpPath")
        try {
          $lines = (Get-ItemProperty -Path $rdpTcpPath -ErrorAction Stop | Select-Object UserAuthentication,SecurityLayer,fEnableCredSspSupport | Format-List * | Out-String).TrimEnd()
          if ($lines) { $output.AddRange($lines -split "`r?`n") }
        } catch {
          $output.Add("RdpTcpError : $_")
        }
      } else {
        $output.Add("PathMissing : $rdpTcpPath")
      }
      $output
    } },
  @{ Name = "Security_SMB"; Description = "SMB server configuration"; Action = {
      try {
        Get-SmbServerConfiguration -ErrorAction Stop | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,EnableInsecureGuestLogons,RejectUnencryptedAccess,EnableAuthenticateUserSharing,RequireSecuritySignature,EnableSecuritySignature,EncryptData | Format-List *
      } catch {
        "Get-SmbServerConfiguration failed: $_"
      }
    } },
  @{ Name = "Security_LSA"; Description = "LSA protection configuration"; Action = {
      $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
      if (Test-Path $path) {
        try {
          Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object RunAsPPL,RunAsPPLBoot,LsaCfgFlags,LmCompatibilityLevel,RestrictSendingNTLMTraffic,RestrictReceivingNTLMTraffic,DisableRestrictedAdmin,NoLMHash | Format-List *
        } catch {
          "Get-ItemProperty failed for $path : $_"
        }
      } else {
        "Registry path not found: $path"
      }
    } },
  @{ Name = "Security_NTLM"; Description = "NTLM configuration"; Action = {
      $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
      if (Test-Path $path) {
        try {
          Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object RestrictSendingNTLMTraffic,RestrictReceivingNTLMTraffic,AuditReceivingNTLMTraffic,AllowNullSessionFallback | Format-List *
        } catch {
          "Get-ItemProperty failed for $path : $_"
        }
      } else {
        "Registry path not found: $path"
      }
    } },
  @{ Name = "Security_SmartScreen"; Description = "SmartScreen configuration"; Action = {
      $output = New-Object System.Collections.Generic.List[string]
      $explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
      if (Test-Path $explorerPath) {
        try {
          $props = Get-ItemProperty -Path $explorerPath -ErrorAction Stop
          $value = $props.PSObject.Properties['SmartScreenEnabled']
          $output.Add("Explorer.SmartScreenEnabled : {0}" -f ($(if ($value) { $value.Value } else { '(not set)' })))
        } catch {
          $output.Add("ExplorerError : $_")
        }
      } else {
        $output.Add("ExplorerMissing : $explorerPath")
      }
      $systemPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
      if (Test-Path $systemPolicy) {
        try {
          $props = Get-ItemProperty -Path $systemPolicy -ErrorAction Stop
          foreach ($name in @('EnableSmartScreen','ShellSmartScreenLevel','EnableAppInstallControl')) {
            $prop = $props.PSObject.Properties[$name]
            $output.Add("Policy.System.{0} : {1}" -f $name, ($(if ($prop) { $prop.Value } else { '(not set)' })))
          }
        } catch {
          $output.Add("Policy.System.Error : $_")
        }
      } else {
        $output.Add("Policy.System.Missing : $systemPolicy")
      }
      $edgePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
      if (Test-Path $edgePolicy) {
        try {
          $props = Get-ItemProperty -Path $edgePolicy -ErrorAction Stop
          foreach ($name in @('SmartScreenEnabled','PreventSmartScreenPromptOverride','PreventSmartScreenPromptOverrideForFiles')) {
            $prop = $props.PSObject.Properties[$name]
            $output.Add("Policy.Edge.{0} : {1}" -f $name, ($(if ($prop) { $prop.Value } else { '(not set)' })))
          }
        } catch {
          $output.Add("Policy.Edge.Error : $_")
        }
      } else {
        $output.Add("Policy.Edge.Missing : $edgePolicy")
      }
      $output
    } },
  @{ Name = "Security_ASR"; Description = "Attack Surface Reduction policy"; Action = {
      $cmd = Get-Command Get-MpPreference -ErrorAction SilentlyContinue
      if (-not $cmd) {
        "Get-MpPreference not available."
      } else {
        try {
          $pref = Get-MpPreference
          $result = [ordered]@{}
          $rules = @()
          if ($pref.AttackSurfaceReductionRules_Ids -and $pref.AttackSurfaceReductionRules_Actions) {
            $ids = @($pref.AttackSurfaceReductionRules_Ids)
            $actions = @($pref.AttackSurfaceReductionRules_Actions)
            $count = [Math]::Min($ids.Count, $actions.Count)
            for ($i = 0; $i -lt $count; $i++) {
              $rules += [pscustomobject]@{ Id = $ids[$i]; Action = $actions[$i] }
            }
          }
          $result.Rules = $rules
          if ($pref.AttackSurfaceReductionOnlyExclusions) {
            $result.Exclusions = @($pref.AttackSurfaceReductionOnlyExclusions)
          }
          ($result | ConvertTo-Json -Depth 5)
        } catch {
          "Get-MpPreference failed: $_"
        }
      }
    } },
  @{ Name = "Security_ExploitProtection"; Description = "Exploit protection (process mitigation)"; Action = {
      $cmd = Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue
      if (-not $cmd) {
        "Get-ProcessMitigation cmdlet not available."
      } else {
        try {
          $data = Get-ProcessMitigation -System
          ($data | ConvertTo-Json -Depth 5)
        } catch {
          "Get-ProcessMitigation -System failed: $_"
        }
      }
    } },
  @{ Name = "Security_WDAC"; Description = "WDAC / Smart App Control configuration"; Action = {
      $result = [ordered]@{}
      try {
        $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $ci = [ordered]@{}
        foreach ($name in @('SecurityServicesConfigured','SecurityServicesRunning','CodeIntegrityPolicyEnforcementStatus','UsermodeCodeIntegrityPolicyEnforcementStatus')) {
          $prop = $dg.PSObject.Properties[$name]
          if ($prop) {
            $ci[$name] = $prop.Value
          }
        }
        $result.DeviceGuard = $ci
      } catch {
        $result.DeviceGuardError = $_.ToString()
      }
      $registry = [ordered]@{}
      $ciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
      if (Test-Path $ciPath) {
        try {
          $props = Get-ItemProperty -Path $ciPath -ErrorAction Stop
          $entry = [ordered]@{}
          foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $entry[$prop.Name] = $prop.Value
          }
          $registry[$ciPath] = $entry
        } catch {
          $registry[$ciPath] = @{ Error = $_.ToString() }
        }
      }
      $sacPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy\SmartAppControl'
      if (Test-Path $sacPath) {
        try {
          $props = Get-ItemProperty -Path $sacPath -ErrorAction Stop
          $entry = [ordered]@{}
          foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $entry[$prop.Name] = $prop.Value
          }
          $registry[$sacPath] = $entry
        } catch {
          $registry[$sacPath] = @{ Error = $_.ToString() }
        }
      }
      if ($registry.Count -gt 0) { $result.Registry = $registry }
      ($result | ConvertTo-Json -Depth 5)
    } },
  @{ Name = "Security_LocalAdmins"; Description = "Local Administrators group members"; Action = {
      $output = New-Object System.Collections.Generic.List[string]
      $cmd = Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue
      if ($cmd) {
        try {
          $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
          if ($members) {
            foreach ($member in $members) {
              $output.Add("Member : {0}" -f $member.Name)
              $output.Add("ObjectClass : {0}" -f $member.ObjectClass)
              if ($member.PSObject.Properties['PrincipalSource']) {
                $output.Add("PrincipalSource : {0}" -f $member.PrincipalSource)
              }
              $output.Add("")
            }
          } else {
            $output.Add("Administrators group returned no members.")
          }
        } catch {
          $output.Add("Get-LocalGroupMember failed: $_")
        }
      } else {
        $output.Add("Get-LocalGroupMember not available; using 'net localgroup'.")
        try {
          $netOutput = net localgroup administrators
          if ($netOutput) { $output.AddRange($netOutput) }
        } catch {
          $output.Add("net localgroup administrators failed: $_")
        }
      }
      $output
    } },
  @{ Name = "Security_LAPS"; Description = "LAPS / PLAP configuration"; Action = {
      $result = [ordered]@{}
      $legacyPath = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
      if (Test-Path $legacyPath) {
        try {
          $props = Get-ItemProperty -Path $legacyPath -ErrorAction Stop
          $entry = [ordered]@{}
          foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $entry[$prop.Name] = $prop.Value
          }
          $result.Legacy = $entry
        } catch {
          $result.LegacyError = $_.ToString()
        }
      }
      $modernPath = 'HKLM:\SOFTWARE\Policies\Microsoft Services\LAPS'
      if (Test-Path $modernPath) {
        try {
          $props = Get-ItemProperty -Path $modernPath -ErrorAction Stop
          $entry = [ordered]@{}
          foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $entry[$prop.Name] = $prop.Value
          }
          $result.WindowsLAPS = $entry
        } catch {
          $result.WindowsLAPSError = $_.ToString()
        }
      }
      if ($result.Count -eq 0) {
        $result.Status = 'No LAPS policy keys found.'
      }
      ($result | ConvertTo-Json -Depth 5)
    } },
  @{ Name = "Security_PowerShellLogging"; Description = "PowerShell logging configuration"; Action = {
      $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
      $result = [ordered]@{}
      if (Test-Path $base) {
        foreach ($sub in @('ScriptBlockLogging','ModuleLogging','Transcription')) {
          $path = Join-Path $base $sub
          if (Test-Path $path) {
            try {
              $props = Get-ItemProperty -Path $path -ErrorAction Stop
              $entry = [ordered]@{}
              foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
                $entry[$prop.Name] = $prop.Value
              }
              $result[$path] = $entry
            } catch {
              $result[$path] = @{ Error = $_.ToString() }
            }
          }
        }
      } else {
        $result.Status = 'PowerShell policy key not found.'
      }
      ($result | ConvertTo-Json -Depth 5)
    } },
  @{ Name = "Security_UAC"; Description = "User Account Control policy"; Action = {
      $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      if (Test-Path $path) {
        try {
          Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop,FilterAdministratorToken | Format-List *
        } catch {
          "Get-ItemProperty failed for $path : $_"
        }
      } else {
        "Registry path not found: $path"
      }
    } },
  @{ Name = "Security_LDAP"; Description = "LDAP signing and channel binding"; Action = {
      $output = New-Object System.Collections.Generic.List[string]
      $clientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
      if (Test-Path $clientPath) {
        try {
          $lines = (Get-ItemProperty -Path $clientPath -ErrorAction Stop | Select-Object LDAPClientIntegrity,LdapEnforceChannelBinding,LdapEnforceChannelBindingLog,ChannelBindingToken | Format-List * | Out-String).TrimEnd()
          if ($lines) { $output.AddRange($lines -split "`r?`n") }
        } catch {
          $output.Add("LDAPClientError : $_")
        }
      } else {
        $output.Add("LDAPClientMissing : $clientPath")
      }
      $serverPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
      if (Test-Path $serverPath) {
        try {
          $lines = (Get-ItemProperty -Path $serverPath -ErrorAction Stop | Select-Object LDAPServerIntegrity,EventLogFlags | Format-List * | Out-String).TrimEnd()
          if ($lines) { $output.AddRange($lines -split "`r?`n") }
        } catch {
          $output.Add("LDAPServerError : $_")
        }
      }
      $output
    } },
  @{ Name = "NetShares"; Description = "File shares (net share)"; Action = { net share } },
  @{ Name = "ScheduledTasks"; Description = "Scheduled task inventory"; Action = { schtasks /query /fo LIST /v } },
  @{ Name = "dsregcmd_status"; Description = "Azure AD registration status (dsregcmd /status)"; Action = { dsregcmd /status } },
  @{ Name = "Whoami"; Description = "Current user context"; Action = { whoami /all } },
  @{ Name = "Uptime"; Description = "Last boot time"; Action = { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } },
  @{ Name = "TopCPU"; Description = "Top CPU processes"; Action = { Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 | Format-Table -AutoSize } },
  @{ Name = "Memory"; Description = "Memory usage summary"; Action = { Get-CimInstance Win32_OperatingSystem | Select @{n='TotalVisibleMemoryMB';e={[math]::round($_.TotalVisibleMemorySize/1024,0)}}, @{n='FreePhysicalMemoryMB';e={[math]::round($_.FreePhysicalMemory/1024,0)}} | Format-List * } }
)

$files = @()
$activity = "Collecting system diagnostics"

for ($i = 0; $i -lt $capturePlan.Count; $i++) {
  $stepNumber = $i + 1
  $step = $capturePlan[$i]
  $status = "[{0}/{1}] {2}" -f $stepNumber, $capturePlan.Count, $step.Description
  $percent = [int](($i / $capturePlan.Count) * 100)
  Write-Progress -Activity $activity -Status $status -PercentComplete $percent
  Write-Host $status

  $timer = [System.Diagnostics.Stopwatch]::StartNew()
  $file = Save-Output -Name $step.Name -Action $step.Action
  $timer.Stop()

  if ($file) {
    Write-Host ("     Saved to {0} ({1:N1}s)" -f $file, $timer.Elapsed.TotalSeconds)
    $files += $file
  }

  $percentComplete = [int](($stepNumber / $capturePlan.Count) * 100)
  Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete
}

Write-Progress -Activity $activity -Completed

# Save copies of the core raw outputs too
Copy-Item -Path $files -Destination $reportDir -Force -ErrorAction SilentlyContinue

# Simple parser: extract key fields from ipconfig /all
Write-Host "Building quick summary from ipconfig_all.txt..."
$ipOut = Get-Content (Join-Path $reportDir "ipconfig_all.txt") -Raw
$Summary = @{
  Hostname = $env:COMPUTERNAME
  Timestamp = $timestamp
  IPv4 = ([regex]::Matches($ipOut,'IPv4 Address[.\s]*?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)') | Select-Object -First 1).Groups[1].Value
  DefaultGateway = ([regex]::Matches($ipOut,'Default Gateway[.\s]*?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)') | Select-Object -First 1).Groups[1].Value
  DNS = ([regex]::Matches($ipOut,'DNS Servers[.\s]*?:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)') | ForEach-Object { $_.Groups[1].Value }) -join ", "
  MACs = ([regex]::Matches($ipOut,'Physical Address[.\s]*?:\s*([0-9A-Fa-f:-]{17}|[0-9A-Fa-f:]{14})') | ForEach-Object { $_.Groups[1].Value }) -join ", "
}
$summaryFile = Join-Path $reportDir "summary.json"
$Summary | ConvertTo-Json | Out-File -FilePath $summaryFile -Encoding UTF8
Write-Host "Summary saved to: $summaryFile"

# Basic HTML report
if (-not $NoHtml) {
  Write-Host "Generating HTML viewer (Report.html)..."
  $htmlFile = Join-Path $reportDir "Report.html"

  $repoRoot = Split-Path $PSScriptRoot -Parent
  $cssSources = @(
    Join-Path $repoRoot 'styles/base.css'
    Join-Path $repoRoot 'styles/layout.css'
    Join-Path $PSScriptRoot 'styles/system-diagnostics-report.css'
  )

  foreach ($source in $cssSources) {
    if (-not (Test-Path $source)) {
      throw "Required stylesheet not found: $source"
    }
  }

  $cssOutputDir = Join-Path $reportDir 'styles'
  if (-not (Test-Path $cssOutputDir)) {
    New-Item -ItemType Directory -Path $cssOutputDir | Out-Null
  }

  $cssOutputPath = Join-Path $cssOutputDir 'system-diagnostics-report.css'
  $cssContent = $cssSources | ForEach-Object { Get-Content -Raw -Path $_ }
  Set-Content -Path $cssOutputPath -Value ($cssContent -join "`n`n") -Encoding UTF8

  $html = @"
<!doctype html>
<html>
<head><meta charset='utf-8'><title>Diagnostics Report - $timestamp</title><link rel='stylesheet' href='styles/system-diagnostics-report.css'></head>
<body class='page diagnostics-page'>
  <h1>Diagnostics Report - $($Summary.Hostname) - $timestamp</h1>
  <div class='diagnostics-section'>
    <h2>Quick Summary</h2>
    <table class='diagnostics-table' cellspacing='0' cellpadding='0'>
      <tr><td>Hostname</td><td>$($Summary.Hostname)</td></tr>
      <tr><td>Local IPv4</td><td>$($Summary.IPv4)</td></tr>
      <tr><td>Default Gateway</td><td>$($Summary.DefaultGateway)</td></tr>
      <tr><td>DNS Servers</td><td>$($Summary.DNS)</td></tr>
      <tr><td>MACs</td><td>$($Summary.MACs)</td></tr>
    </table>
  </div>
  <div class='diagnostics-section'>
    <h2>Raw outputs</h2>
"@

  foreach ($f in Get-ChildItem -Path $reportDir -Filter *.txt | Sort-Object Name) {
    $name = $f.BaseName
    $content = Get-Content $f.FullName -Raw
    $contentEscaped = [System.Web.HttpUtility]::HtmlEncode($content)
    $html += "<h3>$name</h3>`n<pre class='diagnostics-pre'>$contentEscaped</pre>`n"
  }

  $html += "</body></html>"
  $html | Out-File -FilePath $htmlFile -Encoding UTF8
  Write-Host "HTML report written to: $htmlFile"
} else {
  Write-Host "Skipping HTML report generation (-NoHtml specified)."
}

Write-Host "All raw files saved to: $reportDir"
$overallTimer.Stop()
Write-Host ("Diagnostics collection finished in {0:N1}s" -f $overallTimer.Elapsed.TotalSeconds)
