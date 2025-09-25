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

function Test-TcpPort {
  param(
    [Parameter(Mandatory)] [string]$Host,
    [Parameter(Mandatory)] [int]$Port,
    [int]$TimeoutMs = 3000
  )

  $result = [pscustomobject]@{
    Host      = $Host
    Port      = $Port
    Success   = $false
    LatencyMs = $null
    Error     = ''
  }

  if (-not $Host) {
    $result.Error = 'HostNotProvided'
    return $result
  }

  $client = $null
  $waitHandle = $null
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $async = $client.BeginConnect($Host, $Port, $null, $null)
    $waitHandle = $async.AsyncWaitHandle
    if (-not $waitHandle.WaitOne($TimeoutMs)) {
      $stopwatch.Stop()
      $result.Error = 'Timeout'
      return $result
    }

    $client.EndConnect($async)
    $stopwatch.Stop()
    $result.Success = $true
    $result.LatencyMs = [int][math]::Round($stopwatch.Elapsed.TotalMilliseconds)
  } catch {
    $message = $_.Exception.Message
    if ($message) {
      $result.Error = ($message -replace '\r?\n', ' ').Trim()
    } else {
      $result.Error = 'ConnectionFailed'
    }
  } finally {
    if ($waitHandle) {
      try { $waitHandle.Close() } catch {}
    }
    if ($client) {
      try { $client.Close() } catch {}
    }
  }

  return $result
}

function Convert-QueueStatusFlags {
  param($Value)

  if ($null -eq $Value) { return '' }

  $intValue = 0
  if ($Value -is [int]) {
    $intValue = [int]$Value
  } elseif ([int]::TryParse([string]$Value, [ref]$intValue)) {
    $intValue = [int]$intValue
  } else {
    return [string]$Value
  }

  try {
    Add-Type -AssemblyName ReachFramework -ErrorAction SilentlyContinue
    $enumType = [System.Printing.PrintQueueStatus]
  } catch {
    return [string]$Value
  }

  $labels = @()
  foreach ($flag in [Enum]::GetValues($enumType)) {
    $flagValue = [int]$flag
    if ($flagValue -eq 0) { continue }
    if (($intValue -band $flagValue) -ne 0) {
      $labels += $flag.ToString()
    }
  }

  if ($labels.Count -eq 0) { return 'None' }
  return ($labels -join ', ')
}

function Get-PrinterStatusLabel {
  param($Value)

  if ($null -eq $Value) { return '' }

  $map = @{
    1  = 'Other'
    2  = 'Unknown'
    3  = 'Idle'
    4  = 'Printing'
    5  = 'WarmingUp'
    6  = 'Stopped'
    7  = 'Offline'
    8  = 'Paused'
    9  = 'Error'
    10 = 'Busy'
    11 = 'NotAvailable'
    12 = 'Waiting'
    13 = 'Processing'
    14 = 'Initialization'
    15 = 'PowerSave'
    16 = 'PendingDeletion'
    17 = 'IOActive'
    18 = 'ManualFeed'
  }

  $intValue = 0
  if ($Value -is [int]) {
    $intValue = [int]$Value
  } elseif ([int]::TryParse([string]$Value, [ref]$intValue)) {
    $intValue = [int]$intValue
  } else {
    return [string]$Value
  }

  if ($map.ContainsKey($intValue)) { return $map[$intValue] }
  return [string]$intValue
}

function Get-PrinterErrorLabel {
  param($Value)

  if ($null -eq $Value) { return '' }

  $map = @{
    0  = 'Unknown'
    1  = 'Other'
    2  = 'NoError'
    3  = 'LowPaper'
    4  = 'NoPaper'
    5  = 'LowToner'
    6  = 'NoToner'
    7  = 'DoorOpen'
    8  = 'Jammed'
    9  = 'Offline'
    10 = 'ServiceRequested'
    11 = 'OutputBinFull'
    12 = 'NotAvailable'
    13 = 'NoInputTray'
    14 = 'NoFormFeed'
    15 = 'Paused'
    16 = 'ManualFeed'
  }

  $intValue = 0
  if ($Value -is [int]) {
    $intValue = [int]$Value
  } elseif ([int]::TryParse([string]$Value, [ref]$intValue)) {
    $intValue = [int]$intValue
  } else {
    return [string]$Value
  }

  if ($map.ContainsKey($intValue)) { return $map[$intValue] }
  return [string]$intValue
}

function Get-PortProtocolLabel {
  param($Value)

  if ($null -eq $Value) { return '' }

  $intValue = 0
  if ($Value -is [int]) {
    $intValue = [int]$Value
  } elseif ([int]::TryParse([string]$Value, [ref]$intValue)) {
    $intValue = [int]$intValue
  } else {
    return [string]$Value
  }

  switch ($intValue) {
    1 { return 'RAW' }
    2 { return 'LPR' }
    default { return [string]$intValue }
  }
}

function Get-PrinterPortRole {
  param(
    [string]$PortName,
    [string]$PortMonitor,
    [string]$PrinterHostAddress,
    [string]$DeviceUrl
  )

  $host = ''
  $role = 'Local'

  $monitor = if ($PortMonitor) { $PortMonitor.Trim() } else { '' }
  $monitorLower = if ($monitor) { $monitor.ToLowerInvariant() } else { '' }
  $deviceUrl = if ($DeviceUrl) { $DeviceUrl.Trim() } else { '' }

  if ($monitorLower -match 'wsd') {
    $role = 'WSD'
    if ($deviceUrl -match '://([^/]+)') { $host = $matches[1] }
  } elseif ($monitorLower -match 'standard tcp/ip') {
    $role = 'DirectIP'
    if ($PrinterHostAddress) {
      $host = $PrinterHostAddress
    } elseif ($deviceUrl -match '://([^/]+)') {
      $host = $matches[1]
    } elseif ($PortName -match '^IP_(.+)$') {
      $host = $matches[1]
    }
  } elseif ($monitorLower -match 'http' -or $monitorLower -match 'ipp') {
    $role = 'IPP'
    if ($deviceUrl -match '://([^/]+)') {
      $host = $matches[1]
    } elseif ($PrinterHostAddress) {
      $host = $PrinterHostAddress
    }
  } elseif ($monitorLower -match 'local') {
    if ($PortName -match '^\\\\([^\\]+)\\') {
      $role = 'ServerQueue'
      $host = $matches[1]
    } else {
      $role = 'Local'
    }
  } elseif ($deviceUrl -match '^(ipp|http|https)://([^/]+)') {
    $role = 'IPP'
    $host = $matches[2]
  }

  if (-not $host -and $PortName -match '^\\\\([^\\]+)\\') {
    $role = 'ServerQueue'
    $host = $matches[1]
  }

  if (-not $host -and $PortName -match '^IP_(.+)$') {
    if ($role -eq 'Local') { $role = 'DirectIP' }
    $host = $matches[1]
  }

  if (-not $host -and $PrinterHostAddress) { $host = $PrinterHostAddress }

  if ($host) {
    $host = $host.Trim().TrimStart('[').TrimEnd(']')
  }

  if (-not $role) { $role = 'Unknown' }

  return [pscustomobject]@{
    Host = $host
    Role = $role
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
  @{ Name = "Printing_Status"; Description = "Print spooler, queues, ports, drivers, and policies"; Action = {
      Write-Output "### Spooler"
      $spoolerInfo = $null
      try {
        $spoolerInfo = Get-CimInstance Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop
      } catch {
        try { $spoolerInfo = Get-WmiObject Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop } catch {}
      }
      if ($spoolerInfo) {
        Write-Output ("State : {0}" -f $spoolerInfo.State)
        Write-Output ("Status : {0}" -f $spoolerInfo.Status)
        if ($spoolerInfo.PSObject.Properties['Started']) { Write-Output ("Started : {0}" -f ([bool]$spoolerInfo.Started)) }
        if ($spoolerInfo.PSObject.Properties['StartMode']) { Write-Output ("StartMode : {0}" -f $spoolerInfo.StartMode) }
        if ($spoolerInfo.PSObject.Properties['DelayedAutoStart']) { Write-Output ("DelayedAutoStart : {0}" -f ([bool]$spoolerInfo.DelayedAutoStart)) }
        if ($spoolerInfo.PSObject.Properties['StartName']) { Write-Output ("StartName : {0}" -f $spoolerInfo.StartName) }
      } else {
        Write-Output "State : (not found)"
      }
      Write-Output ""

      $printersCim = @()
      try {
        $printersCim = Get-CimInstance Win32_Printer -ErrorAction Stop
      } catch {
        try { $printersCim = Get-WmiObject Win32_Printer -ErrorAction Stop } catch {}
      }

      $printersMap = @{}
      foreach ($printer in $printersCim) {
        if (-not $printer) { continue }
        $name = [string]$printer.Name
        if (-not $name) { continue }
        $entry = [ordered]@{
          Name                        = $name
          Default                     = $printer.Default
          Shared                      = $printer.Shared
          Network                     = $printer.Network
          Local                       = $printer.Local
          Hidden                      = $printer.Hidden
          WorkOffline                 = $printer.WorkOffline
          PortName                    = $printer.PortName
          DriverName                  = $printer.DriverName
          Comment                     = $printer.Comment
          Location                    = $printer.Location
          Attributes                  = $printer.Attributes
          PrinterStatusRaw            = $printer.PrinterStatus
          PrinterStatus               = Get-PrinterStatusLabel $printer.PrinterStatus
          ExtendedPrinterStatusRaw    = $printer.ExtendedPrinterStatus
          ExtendedPrinterStatus       = Get-PrinterStatusLabel $printer.ExtendedPrinterStatus
          DetectedErrorState          = $printer.DetectedErrorState
          DetectedError               = Get-PrinterErrorLabel $printer.DetectedErrorState
          ExtendedDetectedErrorState  = $printer.ExtendedDetectedErrorState
          Availability                = $printer.Availability
          PrintProcessor              = $printer.PrintProcessor
          JobCountSinceLastReset      = $printer.JobCountSinceLastReset
        }
        if ($printer.PSObject.Properties['Published']) { $entry['Published'] = $printer.Published }
        $printersMap[$name] = $entry
      }

      $pmPrinters = @()
      $getPrinterCmd = Get-Command Get-Printer -ErrorAction SilentlyContinue
      if ($getPrinterCmd) {
        try { $pmPrinters = Get-Printer -ErrorAction Stop } catch {}
      }
      foreach ($pm in $pmPrinters) {
        if (-not $pm) { continue }
        $name = [string]$pm.Name
        if (-not $name) { continue }
        if (-not $printersMap.ContainsKey($name)) {
          $printersMap[$name] = [ordered]@{ Name = $name }
        }
        $entry = $printersMap[$name]
        if ($pm.PSObject.Properties['Default']) { $entry['Default'] = $pm.Default }
        if ($pm.PSObject.Properties['Shared']) { $entry['Shared'] = $pm.Shared }
        if ($pm.PSObject.Properties['WorkOffline']) { $entry['WorkOffline'] = $pm.WorkOffline }
        if ($pm.PSObject.Properties['QueueStatus']) {
          $entry['QueueStatusRaw'] = $pm.QueueStatus
          $entry['QueueStatus'] = Convert-QueueStatusFlags $pm.QueueStatus
        }
        if ($pm.PSObject.Properties['JobCount']) { $entry['JobCount'] = $pm.JobCount }
        if ($pm.PSObject.Properties['Type']) { $entry['Type'] = $pm.Type }
        if ($pm.PSObject.Properties['Comment'] -and -not $entry['Comment']) { $entry['Comment'] = $pm.Comment }
        if ($pm.PSObject.Properties['Published']) { $entry['Published'] = $pm.Published }
      }

      Write-Output "### Printers"
      if ($printersMap.Count -eq 0) {
        Write-Output "Status : NoneFound"
        Write-Output ""
      } else {
        foreach ($printerName in ($printersMap.Keys | Sort-Object)) {
          $entry = $printersMap[$printerName]
          Write-Output ("#### Printer: {0}" -f $printerName)
          foreach ($key in @('Default','Shared','Network','Local','Hidden','WorkOffline','Published','PortName','DriverName','Type','JobCount','JobCountSinceLastReset','QueueStatusRaw','QueueStatus','PrinterStatusRaw','PrinterStatus','ExtendedPrinterStatusRaw','ExtendedPrinterStatus','DetectedErrorState','DetectedError','ExtendedDetectedErrorState','Availability','PrintProcessor','Attributes','Comment','Location')) {
            if ($entry.ContainsKey($key)) {
              $value = $entry[$key]
              if ($null -eq $value) { $value = '' }
              elseif ($value -is [array]) { $value = ($value -join ', ') }
              Write-Output ("{0} : {1}" -f $key, $value)
            }
          }
          Write-Output ""
        }
      }

      Write-Output "### Ports"
      $portRecords = @()
      $printerPorts = @()
      $getPrinterPortCmd = Get-Command Get-PrinterPort -ErrorAction SilentlyContinue
      if ($getPrinterPortCmd) {
        try { $printerPorts = Get-PrinterPort -ErrorAction Stop } catch {}
      }
      if (-not $printerPorts -or $printerPorts.Count -eq 0) {
        try { $printerPorts = Get-CimInstance Win32_PrinterPort -ErrorAction Stop } catch {}
      }
      foreach ($port in $printerPorts) {
        if (-not $port) { continue }
        $portName = [string]$port.Name
        if (-not $portName) { continue }
        $record = [ordered]@{ Name = $portName }
        foreach ($prop in @('PortMonitor','PrinterHostAddress','DeviceURL','PortNumber','Protocol','SNMPEnabled','SNMPCommunity')) {
          if ($port.PSObject.Properties[$prop]) {
            $value = $port.$prop
            if ($prop -eq 'Protocol') {
              $record[$prop] = $value
              $record['ProtocolLabel'] = Get-PortProtocolLabel $value
            } else {
              $record[$prop] = $value
            }
          }
        }
        $roleInfo = Get-PrinterPortRole -PortName $portName -PortMonitor ($record['PortMonitor']) -PrinterHostAddress ($record['PrinterHostAddress']) -DeviceUrl ($record['DeviceURL'])
        if ($roleInfo.Host) { $record['Host'] = $roleInfo.Host }
        if ($roleInfo.Role) { $record['Role'] = $roleInfo.Role }
        $portRecords += $record
      }
      if ($portRecords.Count -eq 0) {
        Write-Output "Status : NoPortsFound"
        Write-Output ""
      } else {
        foreach ($record in ($portRecords | Sort-Object Name)) {
          Write-Output ("#### Port: {0}" -f $record['Name'])
          foreach ($key in @('PortMonitor','PrinterHostAddress','DeviceURL','PortNumber','Protocol','ProtocolLabel','SNMPEnabled','SNMPCommunity','Host','Role')) {
            if ($record.ContainsKey($key)) {
              $value = $record[$key]
              if ($null -eq $value) { $value = '' }
              elseif ($value -is [bool]) { $value = [bool]$value }
              Write-Output ("{0} : {1}" -f $key, $value)
            }
          }
          Write-Output ""
        }
      }

      Write-Output "### Drivers"
      $drivers = @()
      $driverCmd = Get-Command Get-PrinterDriver -ErrorAction SilentlyContinue
      if ($driverCmd) {
        try { $drivers = Get-PrinterDriver -ErrorAction Stop } catch {}
      }
      if (-not $drivers -or $drivers.Count -eq 0) {
        try { $drivers = Get-CimInstance Win32_PrinterDriver -ErrorAction Stop } catch {}
      }
      if (-not $drivers -or $drivers.Count -eq 0) {
        Write-Output "Status : NoDriversFound"
        Write-Output ""
      } else {
        foreach ($driver in ($drivers | Sort-Object Name)) {
          if (-not $driver) { continue }
          $name = [string]$driver.Name
          if (-not $name) { continue }
          Write-Output ("#### Driver: {0}" -f $name)
          $typeValue = $null
          if ($driver.PSObject.Properties['Type']) { $typeValue = $driver.Type }
          foreach ($key in @('Manufacturer','Type','IsPackaged','MajorVersion','MinorVersion','DriverVersion','InfPath')) {
            if ($driver.PSObject.Properties[$key]) {
              $value = $driver.$key
              if ($value -is [bool]) { $value = [bool]$value }
              Write-Output ("{0} : {1}" -f $key, $value)
            }
          }
          if ($null -ne $typeValue) {
            $intType = $null
            if ($typeValue -is [int]) { $intType = [int]$typeValue }
            elseif ([int]::TryParse([string]$typeValue, [ref]$intType)) { $intType = [int]$intType }
            if ($null -ne $intType) {
              switch ($intType) {
                3 { Write-Output "TypeLabel : Type3" }
                4 { Write-Output "TypeLabel : Type4" }
                default { Write-Output ("TypeLabel : {0}" -f $intType) }
              }
            }
          }
          Write-Output ""
        }
      }

      Write-Output "### Configurations"
      $configCmd = Get-Command Get-PrintConfiguration -ErrorAction SilentlyContinue
      if ($configCmd -and $printersMap.Count -gt 0) {
        foreach ($printerName in ($printersMap.Keys | Sort-Object)) {
          try { $config = Get-PrintConfiguration -PrinterName $printerName -ErrorAction Stop } catch { $config = $null }
          if (-not $config) { continue }
          Write-Output ("#### Printer: {0}" -f $printerName)
          foreach ($key in @('DuplexingMode','Collate','ColorMode','PaperSize','NUp','Quality','Orientation')) {
            if ($config.PSObject.Properties[$key]) {
              $value = $config.$key
              if ($value -is [bool]) { $value = [bool]$value }
              Write-Output ("{0} : {1}" -f $key, $value)
            }
          }
          Write-Output ""
        }
      } else {
        Write-Output "Status : ConfigurationDataUnavailable"
        Write-Output ""
      }

      Write-Output "### Jobs"
      $jobs = @()
      $getPrintJobCmd = Get-Command Get-PrintJob -ErrorAction SilentlyContinue
      if ($getPrintJobCmd) {
        try { $jobs = Get-PrintJob -ErrorAction Stop } catch {}
      }
      if (-not $jobs -or $jobs.Count -eq 0) {
        try { $jobs = Get-CimInstance Win32_PrintJob -ErrorAction Stop } catch {}
      }
      if (-not $jobs -or $jobs.Count -eq 0) {
        Write-Output "Status : NoJobs"
        Write-Output ""
      } else {
        $now = Get-Date
        foreach ($job in $jobs) {
          if (-not $job) { continue }
          $printerName = $null
          if ($job.PSObject.Properties['PrinterName']) {
            $printerName = [string]$job.PrinterName
          } elseif ($job.PSObject.Properties['Name']) {
            $nameValue = [string]$job.Name
            if ($nameValue -match '^([^,]+),') { $printerName = $matches[1] }
          }
          if (-not $printerName) { $printerName = '(unknown)' }
          Write-Output ("#### Job: {0}" -f $printerName)
          if ($job.PSObject.Properties['Id']) { Write-Output ("JobId : {0}" -f $job.Id) }
          elseif ($job.PSObject.Properties['JobId']) { Write-Output ("JobId : {0}" -f $job.JobId) }
          if ($job.PSObject.Properties['DocumentName']) { Write-Output ("Document : {0}" -f $job.DocumentName) }
          elseif ($job.PSObject.Properties['Document']) { Write-Output ("Document : {0}" -f $job.Document) }
          if ($job.PSObject.Properties['UserName']) { Write-Output ("UserName : {0}" -f $job.UserName) }
          if ($job.PSObject.Properties['Size']) { Write-Output ("SizeBytes : {0}" -f $job.Size) }
          elseif ($job.PSObject.Properties['TotalBytes']) { Write-Output ("SizeBytes : {0}" -f $job.TotalBytes) }
          if ($job.PSObject.Properties['TotalPages']) { Write-Output ("TotalPages : {0}" -f $job.TotalPages) }
          if ($job.PSObject.Properties['JobStatus']) { Write-Output ("JobStatus : {0}" -f $job.JobStatus) }
          if ($job.PSObject.Properties['Status']) { Write-Output ("Status : {0}" -f $job.Status) }
          $submitted = $null
          if ($job.PSObject.Properties['SubmittedTime']) {
            $submitted = $job.SubmittedTime
          } elseif ($job.PSObject.Properties['TimeSubmitted']) {
            $submittedRaw = $job.TimeSubmitted
            if ($submittedRaw -is [datetime]) {
              $submitted = $submittedRaw
            } elseif ($submittedRaw -is [string] -and $submittedRaw) {
              try { $submitted = [System.Management.ManagementDateTimeConverter]::ToDateTime($submittedRaw) } catch { $submitted = $null }
            }
          }
          if ($submitted -is [datetime]) {
            try { $submittedUtc = $submitted.ToUniversalTime() } catch { $submittedUtc = $submitted }
            Write-Output ("SubmittedTime : {0:o}" -f $submittedUtc)
            $ageMinutes = [int][math]::Max(0, [math]::Ceiling(($now - $submitted).TotalMinutes))
            Write-Output ("ElapsedMinutes : {0}" -f $ageMinutes)
          }
          Write-Output ""
        }
      }

      Write-Output "### Policies"
      $policySpecs = @(
        @{ Name = 'RestrictDriverInstallationToAdministrators'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers' },
        @{ Name = 'PackagePointAndPrintOnly'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
        @{ Name = 'PackagePointAndPrintServerList'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
        @{ Name = 'NoWarningNoElevationOnInstall'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
        @{ Name = 'NoWarningNoElevationOnUpdate'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
        @{ Name = 'UpdatePromptSettings'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
        @{ Name = 'InForest'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' },
        @{ Name = 'TrustedServers'; Path = 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' }
      )
      $policyCaptured = $false
      foreach ($spec in $policySpecs) {
        $path = $spec.Path
        $name = $spec.Name
        if (-not (Test-Path $path)) { continue }
        try { $props = Get-ItemProperty -Path $path -ErrorAction Stop } catch { continue }
        if (-not $props) { continue }
        $prop = $props.PSObject.Properties[$name]
        if (-not $prop) { continue }
        $value = $prop.Value
        if ($null -eq $value) { continue }
        if ($value -is [array]) {
          $valueString = ($value | ForEach-Object { ($_ | Out-String).Trim() } | Where-Object { $_ }) -join ', '
        } else {
          $valueString = [string]$value
        }
        if ([string]::IsNullOrWhiteSpace($valueString)) { continue }
        Write-Output ("Policy.{0} : {1}" -f $name, $valueString.Trim())
        $policyCaptured = $true
      }
      if (-not $policyCaptured) { Write-Output "PolicyStatus : NoneCaptured" }
      Write-Output ""

      Write-Output "### NetworkTests"
      $portLookup = @{}
      foreach ($record in $portRecords) {
        $portLookup[$record['Name']] = $record
      }
      $hostRecords = @{}
      foreach ($entry in $printersMap.Values) {
        if (-not $entry.ContainsKey('PortName')) { continue }
        $portName = $entry['PortName']
        if (-not $portName) { continue }
        if (-not $portLookup.ContainsKey($portName)) { continue }
        $portInfo = $portLookup[$portName]
        $host = if ($portInfo.ContainsKey('Host')) { $portInfo['Host'] } else { '' }
        if (-not $host) { continue }
        $role = if ($portInfo.ContainsKey('Role')) { $portInfo['Role'] } else { 'Local' }
        $hostKey = $host.ToLowerInvariant()
        if (-not $hostRecords.ContainsKey($hostKey)) {
          $hostRecords[$hostKey] = @{ Host = $host; Roles = @(); Printers = @(); Ports = @() }
        }
        $record = $hostRecords[$hostKey]
        if ($role -and ($record.Roles -notcontains $role)) { $record.Roles += $role }
        if ($record.Printers -notcontains $entry['Name']) { $record.Printers += $entry['Name'] }
        if ($record.Ports -notcontains $portName) { $record.Ports += $portName }
      }
      $testPlans = @()
      $planKeys = @{}
      foreach ($record in $hostRecords.Values) {
        $roles = $record.Roles | Sort-Object -Unique
        foreach ($role in $roles) {
          if ($role -eq 'ServerQueue') {
            $portsToTest = @(135, 445)
          } elseif ($role -eq 'DirectIP' -or $role -eq 'IPP') {
            $portsToTest = @(9100, 631)
          } else {
            continue
          }
          foreach ($port in $portsToTest) {
            $key = "{0}|{1}|{2}" -f $record.Host.ToLowerInvariant(), $role, $port
            if ($planKeys.ContainsKey($key)) { continue }
            $planKeys[$key] = $true
            $testPlans += [pscustomobject]@{
              Host        = $record.Host
              Role        = $role
              Port        = $port
              Printers    = $record.Printers
              SourcePorts = $record.Ports
            }
          }
        }
      }
      if ($testPlans.Count -eq 0) {
        Write-Output "Targets : (none)"
      } else {
        foreach ($plan in ($testPlans | Sort-Object Host, Role, Port)) {
          $result = Test-TcpPort -Host $plan.Host -Port $plan.Port
          Write-Output ("#### Target: {0}" -f $plan.Host)
          Write-Output ("Role : {0}" -f $plan.Role)
          Write-Output ("Port : {0}" -f $plan.Port)
          Write-Output ("Printers : {0}" -f (($plan.Printers | Sort-Object) -join ', '))
          Write-Output ("SourcePorts : {0}" -f (($plan.SourcePorts | Sort-Object) -join ', '))
          Write-Output ("Success : {0}" -f $result.Success)
          if ($null -ne $result.LatencyMs) { Write-Output ("LatencyMs : {0}" -f $result.LatencyMs) }
          if ($result.Error) { Write-Output ("Error : {0}" -f $result.Error) } else { Write-Output "Error : " }
          Write-Output ""
        }
      }
    } },
  @{ Name = "PrintService_Events"; Description = "PrintService event logs (last 7 days)"; Action = {
      $logs = @('Microsoft-Windows-PrintService/Admin','Microsoft-Windows-PrintService/Operational')
      $start = (Get-Date).AddDays(-7)
      foreach ($log in $logs) {
        Write-Output ("### Log: {0}" -f $log)
        try {
          $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -ErrorAction Stop |
            Sort-Object TimeCreated |
            Select-Object -Last 200
        } catch {
          Write-Output ("LogError : {0}" -f $_)
          Write-Output ""
          continue
        }
        if (-not $events -or $events.Count -eq 0) {
          Write-Output "LogStatus : NoEventsInRange"
          Write-Output ""
          continue
        }
        foreach ($event in $events) {
          $timeCreated = $null
          if ($event.TimeCreated) {
            try { $timeCreated = $event.TimeCreated.ToUniversalTime() } catch { $timeCreated = $event.TimeCreated }
          }
          $levelName = $event.LevelDisplayName
          if (-not $levelName) {
            switch ($event.Level) {
              1 { $levelName = 'Critical' }
              2 { $levelName = 'Error' }
              3 { $levelName = 'Warning' }
              4 { $levelName = 'Information' }
              5 { $levelName = 'Verbose' }
            }
          }
          $message = ''
          try {
            if ($event.Message) { $message = ($event.Message -replace '\r?\n',' ').Trim() }
          } catch {}
          Write-Output ("EventID : {0}" -f $event.Id)
          if ($timeCreated) { Write-Output ("TimeCreated : {0:o}" -f $timeCreated) }
          if ($event.PSObject.Properties['Level']) { Write-Output ("Level : {0}" -f $event.Level) }
          if ($levelName) { Write-Output ("LevelDisplayName : {0}" -f $levelName) }
          if ($event.PSObject.Properties['ProviderName']) { Write-Output ("ProviderName : {0}" -f $event.ProviderName) }
          if ($event.PSObject.Properties['TaskDisplayName'] -and $event.TaskDisplayName) { Write-Output ("Task : {0}" -f $event.TaskDisplayName) }
          Write-Output ("Message : {0}" -f $message)
          Write-Output ""
        }
      }
    } },
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
