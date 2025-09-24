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
  @{ Name = "NetShares"; Description = "File shares (net share)"; Action = { net share } },
  @{ Name = "ScheduledTasks"; Description = "Scheduled task inventory"; Action = { schtasks /query /fo LIST /v } },
  @{ Name = "dsregcmd_status"; Description = "Azure AD registration status (dsregcmd /status)"; Action = { dsregcmd /status } },
  @{ Name = "Whoami"; Description = "Current user context"; Action = { whoami /all } },
  @{ Name = "Uptime"; Description = "Last boot time"; Action = { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } },
  @{ Name = "FastStartupStatus"; Description = "Fast Startup (hiberboot) configuration"; Action = {
      $regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power'
      Write-Output ("Registry Path : {0}" -f $regPath)

      try {
        $hiberboot = Get-ItemProperty -Path $regPath -Name HiberbootEnabled -ErrorAction Stop | Select-Object -ExpandProperty HiberbootEnabled
        Write-Output ("HiberbootEnabled : {0}" -f $hiberboot)
        if ($null -ne $hiberboot) {
          $isEnabled = $null
          try {
            $isEnabled = [bool]([int]$hiberboot)
          } catch {
            if ($hiberboot -is [bool]) {
              $isEnabled = [bool]$hiberboot
            } elseif ($hiberboot -is [string] -and $hiberboot -match '^(0|1)$') {
              $isEnabled = ([int]$hiberboot -ne 0)
            } elseif ($hiberboot -is [string] -and $hiberboot -match '^0x[0-9a-f]+$') {
              $isEnabled = ([Convert]::ToInt32($hiberboot, 16) -ne 0)
            }
          }

          if ($null -ne $isEnabled) {
            $statusLabel = if ($isEnabled) { 'Enabled' } else { 'Disabled' }
            Write-Output ("Fast Startup Status : {0}" -f $statusLabel)
          }
        }
      } catch {
        Write-Output ("HiberbootEnabled query failed: {0}" -f $_)
      }

      Write-Output ""
      Write-Output "powercfg /a output:"
      try {
        powercfg /a
      } catch {
        Write-Output ("powercfg /a failed: {0}" -f $_)
      }
    } },
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
