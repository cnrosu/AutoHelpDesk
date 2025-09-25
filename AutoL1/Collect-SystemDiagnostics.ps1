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
  $result = $result.Trim('\')
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

  $domainSet = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($candidate in $ctx.DomainCandidates) {
    $normalized = Normalize-DomainName $candidate
    if ($normalized) { $null = $domainSet.Add($normalized) }
  }
  $ctx.DomainCandidates = $domainSet.ToArray() | Sort-Object -Unique

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

  $forestSet = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($candidate in $ctx.ForestCandidates + $ctx.DomainCandidates) {
    $normalizedForest = Normalize-DomainName $candidate
    if ($normalizedForest) { $null = $forestSet.Add($normalizedForest) }
  }
  $ctx.ForestCandidates = $forestSet.ToArray() | Sort-Object -Unique

  if (-not $ctx.DomainDnsName -and $ctx.DomainCandidates.Count -gt 0) {
    $ctx.DomainDnsName = $ctx.DomainCandidates[0]
  }

  return [pscustomobject]$ctx
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
  @{ Name = "NetShares"; Description = "File shares (net share)"; Action = { net share } },
  @{ Name = "ScheduledTasks"; Description = "Scheduled task inventory"; Action = { schtasks /query /fo LIST /v } },
  @{ Name = "dsregcmd_status"; Description = "Azure AD registration status (dsregcmd /status)"; Action = { dsregcmd /status } },
  @{ Name = "AD_DomainStatus"; Description = "Active Directory domain status"; Action = {
      $ctx = Get-ADCollectorContext
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
    } },
  @{ Name = "AD_DCDiscovery"; Description = "Active Directory DC discovery (nltest & DNS SRV)"; Action = {
      $ctx = Get-ADCollectorContext
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
    } },
  @{ Name = "AD_DCPortTests"; Description = "Active Directory domain controller port checks"; Action = {
      $ctx = Get-ADCollectorContext
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

      $dcSet = New-Object 'System.Collections.Generic.HashSet[string]'
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

      $dcListFinal = $dcSet.ToArray() | Sort-Object
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
            $ping = if ($null -ne $result.PingSucceeded) { $result.PingSucceeded } else { $false }
            $latency = $null
            if ($ping -and $result.PingReplyDetails -and $null -ne $result.PingReplyDetails.RoundtripTime) {
              try { $latency = [int]$result.PingReplyDetails.RoundtripTime } catch { $latency = $result.PingReplyDetails.RoundtripTime }
            }
            $latencyText = if ($latency -ne $null) { $latency } else { '' }
            Write-Output ("PortResult : {0} | Port={1} | Success={2} | RemoteAddress={3} | PingSucceeded={4} | LatencyMs={5}" -f $dc, $port, $tcp, (if ($addr) { $addr } else { '' }), $ping, $latencyText)
          } catch {
            Write-Output ("PortResult : {0} | Port={1} | Success=Error | Error={2}" -f $dc, $port, $_)
          }
        }
        Write-Output ""
      }
    } },
  @{ Name = "AD_SYSVOL"; Description = "Active Directory SYSVOL/NETLOGON access"; Action = {
      $ctx = Get-ADCollectorContext
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
    } },
  @{ Name = "AD_Time"; Description = "Time service status"; Action = {
      Write-Output ("Timestamp : {0:o}" -f (Get-Date))
      try {
        $status = w32tm /query /status 2>&1
        $statusExit = $LASTEXITCODE
      } catch {
        $status = @("w32tm /query /status failed: {0}" -f $_)
        $statusExit = -1
      }
      Write-Output "## w32tm /query /status"
      if ($status) { $status | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
      Write-Output ("StatusExitCode : {0}" -f $statusExit)
      if ($status) {
        $statusText = ($status -join "`n")
        $offsetMatch = [regex]::Match($statusText,'(?im)^(?:Phase Offset|Offset)\s*:\s*([+-]?[0-9\.]+)s')
        if ($offsetMatch.Success) { Write-Output ("PhaseOffsetSeconds : {0}" -f $offsetMatch.Groups[1].Value.Trim()) }
        $sourceMatch = [regex]::Match($statusText,'(?im)^\s*Source\s*:\s*(.+)$')
        if ($sourceMatch.Success) { Write-Output ("TimeSource : {0}" -f $sourceMatch.Groups[1].Value.Trim()) }
        $lastSyncMatch = [regex]::Match($statusText,'(?im)^\s*Last Successful Sync Time\s*:\s*(.+)$')
        if ($lastSyncMatch.Success) { Write-Output ("LastSuccessfulSync : {0}" -f $lastSyncMatch.Groups[1].Value.Trim()) }
      }
      Write-Output ""
      try {
        $peers = w32tm /query /peers 2>&1
        $peersExit = $LASTEXITCODE
      } catch {
        $peers = @("w32tm /query /peers failed: {0}" -f $_)
        $peersExit = -1
      }
      Write-Output "## w32tm /query /peers"
      if ($peers) { $peers | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
      Write-Output ("PeersExitCode : {0}" -f $peersExit)
    } },
  @{ Name = "AD_Kerberos"; Description = "Kerberos ticket status and recent failures"; Action = {
      $ctx = Get-ADCollectorContext
      Write-Output ("Timestamp : {0:o}" -f (Get-Date))
      $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
      Write-Output ("PartOfDomain : {0}" -f $partText)
      Write-Output "## klist"
      try {
        $klistOutput = klist 2>&1
        if ($klistOutput) { $klistOutput | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
      } catch {
        Write-Output ("klist failed: {0}" -f $_)
      }
      Write-Output ""
      $startTime = (Get-Date).AddHours(-72)
      try {
        $events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=@(4768,4771,4776); StartTime=$startTime } -ErrorAction Stop
        $count = if ($events) { $events.Count } else { 0 }
        Write-Output ("KerberosEventCount : {0}" -f $count)
        if ($events) {
          $sorted = $events | Sort-Object TimeCreated -Descending | Select-Object -First 25
          foreach ($ev in $sorted) {
            $msg = ($ev.Message -replace "[\r\n]+", ' ').Trim()
            Write-Output ("KerberosEvent : Id={0}; Time={1:o}; Provider={2}; Message={3}" -f $ev.Id, $ev.TimeCreated, $ev.ProviderName, $msg)
          }
        }
      } catch {
        Write-Output ("KerberosEventError : {0}" -f $_)
      }
    } },
  @{ Name = "AD_SecureChannel"; Description = "Machine secure channel verification"; Action = {
      $ctx = Get-ADCollectorContext
      Write-Output ("Timestamp : {0:o}" -f (Get-Date))
      $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
      Write-Output ("PartOfDomain : {0}" -f $partText)
      if ($ctx.PartOfDomain -ne $true) {
        Write-Output "Status : Skipped (NotDomainJoined)"
        return
      }

      try {
        $scResult = Test-ComputerSecureChannel -ErrorAction Stop
        Write-Output ("SecureChannelResult : {0}" -f $scResult)
      } catch {
        Write-Output "SecureChannelResult : Error"
        Write-Output ("SecureChannelError : {0}" -f $_)
      }

      $queryTarget = $null
      if ($ctx.DomainDnsName) {
        $queryTarget = $ctx.DomainDnsName
      } elseif ($ctx.Domain) {
        $queryTarget = $ctx.Domain
      } elseif ($ctx.DomainCandidates -and $ctx.DomainCandidates.Count -gt 0) {
        $queryTarget = $ctx.DomainCandidates[0]
      }

      Write-Output ("SecureChannelQueryTarget : {0}" -f (if ($queryTarget) { $queryTarget } else { '(unknown)' }))
      if ($queryTarget) {
        try {
          $nlOutput = nltest /sc_query:$queryTarget 2>&1
          $nlExit = $LASTEXITCODE
        } catch {
          $nlOutput = @("nltest /sc_query failed: {0}" -f $_)
          $nlExit = -1
        }
      } else {
        $nlOutput = @("nltest /sc_query skipped: domain unknown")
        $nlExit = -1
      }

      Write-Output ("SecureChannelNltestExitCode : {0}" -f $nlExit)
      Write-Output "## nltest /sc_query"
      if ($nlOutput) { $nlOutput | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
    } },
  @{ Name = "AD_GPO"; Description = "Group Policy results and recent errors"; Action = {
      $ctx = Get-ADCollectorContext
      Write-Output ("Timestamp : {0:o}" -f (Get-Date))
      $partText = if ($null -eq $ctx.PartOfDomain) { 'Unknown' } else { [string]$ctx.PartOfDomain }
      Write-Output ("PartOfDomain : {0}" -f $partText)
      if ($ctx.PartOfDomain -ne $true) {
        Write-Output "Status : Skipped (NotDomainJoined)"
        return
      }

      Write-Output "## gpresult /r /scope computer"
      try {
        $gpComputer = gpresult /r /scope computer 2>&1
        $gpComputerExit = $LASTEXITCODE
      } catch {
        $gpComputer = @("gpresult /r /scope computer failed: {0}" -f $_)
        $gpComputerExit = -1
      }
      if ($gpComputer) { $gpComputer | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
      Write-Output ("GPResultComputerExitCode : {0}" -f $gpComputerExit)
      Write-Output ""

      Write-Output "## gpresult /r /scope user"
      try {
        $gpUser = gpresult /r /scope user 2>&1
        $gpUserExit = $LASTEXITCODE
      } catch {
        $gpUser = @("gpresult /r /scope user failed: {0}" -f $_)
        $gpUserExit = -1
      }
      if ($gpUser) { $gpUser | ForEach-Object { Write-Output $_ } } else { Write-Output "(no output)" }
      Write-Output ("GPResultUserExitCode : {0}" -f $gpUserExit)
      Write-Output ""

      $startTime = (Get-Date).AddHours(-72)
      try {
        $gpoEvents = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=@(1058,1030); StartTime=$startTime } -ErrorAction Stop
        $count = if ($gpoEvents) { $gpoEvents.Count } else { 0 }
        Write-Output ("GPOEventCount : {0}" -f $count)
        if ($gpoEvents) {
          $sorted = $gpoEvents | Sort-Object TimeCreated -Descending | Select-Object -First 25
          foreach ($ev in $sorted) {
            $msg = ($ev.Message -replace "[\r\n]+", ' ').Trim()
            Write-Output ("GPOEvent : Id={0}; Time={1:o}; Provider={2}; Message={3}" -f $ev.Id, $ev.TimeCreated, $ev.ProviderName, $msg)
          }
        }
      } catch {
        Write-Output ("GPOEventError : {0}" -f $_)
      }
    } },
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
