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

$ThrottleLimit = 6
$TaskTimeoutSec = 60

$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$reportDir = Join-Path -Path $OutRoot -ChildPath $timestamp
New-Item -Path $reportDir -ItemType Directory -Force | Out-Null

$overallTimer = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "Starting diagnostics collection..."
Write-Host "Output folder: $reportDir"

# Launch a background job for an individual task
function Start-CollectionJob {
  param(
    [Parameter(Mandatory)] [string]$Key,
    [Parameter(Mandatory)] [string]$Description,
    [Parameter(Mandatory)] [scriptblock]$Script,
    [Parameter(Mandatory)] [string]$OutDir
  )

  $outputPath = Join-Path $OutDir ("$Key.txt")
  $startTime = Get-Date
  $headerLine = "===== $Key : $startTime ====="

  $jobScript = {
    param($TaskKey, $TaskScript, $TaskOutputPath, $HeaderLine)

    Set-Content -Path $TaskOutputPath -Value @("", $HeaderLine, "") -Encoding UTF8
    try {
      & $TaskScript *>&1 | Out-File -FilePath $TaskOutputPath -Encoding UTF8 -Append
    } catch {
      Set-Content -Path $TaskOutputPath -Value @("", $HeaderLine, "", "ERROR running $TaskKey : $_") -Encoding UTF8
      throw
    }
  }

  $job = Start-Job -Name $Key -ScriptBlock $jobScript -ArgumentList $Key, $Script, $outputPath, $headerLine

  return [pscustomobject]@{
    Key = $Key
    Description = $Description
    Job = $job
    OutputPath = $outputPath
    StartTime = $startTime
    HeaderLine = $headerLine
  }
}

$capturePlan = @(
  @{ Key = "ipconfig_all"; Description = "Detailed IP configuration (ipconfig /all)"; Script = { ipconfig /all } },
  @{ Key = "route_print"; Description = "Routing table (route print)"; Script = { route print } },
  @{ Key = "netstat_ano"; Description = "Active connections and ports (netstat -ano)"; Script = { netstat -ano } },
  @{ Key = "arp_table"; Description = "ARP cache entries (arp -a)"; Script = { arp -a } },
  @{ Key = "nslookup_google"; Description = "DNS resolution test for google.com"; Script = { nslookup google.com } },
  @{ Key = "tracert_google"; Description = "Traceroute to 8.8.8.8"; Script = { tracert -d -h 10 8.8.8.8 } },
  @{ Key = "ping_google"; Description = "Ping test to 8.8.8.8"; Script = { ping -n 4 8.8.8.8 } },
  @{ Key = "TestNetConnection_Outlook443"; Description = "Test HTTPS connectivity to outlook.office365.com"; Script = {
      $testNetCmd = Get-Command Test-NetConnection -ErrorAction SilentlyContinue
      if (-not $testNetCmd) {
        "Test-NetConnection cmdlet not available on this system."
      } else {
        Test-NetConnection outlook.office365.com -Port 443 -WarningAction SilentlyContinue |
          Format-List * |
          Out-String
      }
    } },
  @{ Key = "Outlook_OST"; Description = "Outlook OST cache inventory"; Script = {
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
  @{ Key = "Autodiscover_DNS"; Description = "Autodiscover DNS lookups"; Script = {
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
  @{ Key = "Outlook_SCP"; Description = "Autodiscover SCP search (Active Directory)"; Script = {
      try {
        $root = [ADSI]"LDAP://RootDSE"
        $configNc = $root.configurationNamingContext
        if (-not $configNc) {
          "configurationNamingContext not available on this system."
        } else {
          $searcher = New-Object System.DirectoryServices.DirectorySearcher
          $searcher.SearchRoot = [ADSI]("LDAP://$configNc")
          $searcher.Filter = "(&(objectClass=serviceConnectionPoint)(|(keywords=77378F46-2C66-4AA9-A6A6-3E5E921F0A02)(keywords=77378F46-2C66-4AA9-A6A6-3E5E921F0A03)))"
          $searcher.PageSize = 1000
          [void]$searcher.PropertiesToLoad.Add('name')
          [void]$searcher.PropertiesToLoad.Add('serviceBindingInformation')
          [void]$searcher.PropertiesToLoad.Add('keywords')
          [void]$searcher.PropertiesToLoad.Add('distinguishedName')
          [void]$searcher.PropertiesToLoad.Add('whenChanged')
          $results = $searcher.FindAll()
          if (-not $results -or $results.Count -eq 0) {
            "No Autodiscover SCPs found."
          } else {
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
        }
      } catch {
        "Autodiscover SCP lookup failed: $_"
      }
    } },
  @{ Key = "systeminfo"; Description = "General system information"; Script = { systeminfo } },
  @{ Key = "OS_CIM"; Description = "Operating system CIM inventory"; Script = { Get-CimInstance Win32_OperatingSystem | Format-List * } },
  @{ Key = "ComputerInfo"; Description = "ComputerInfo snapshot"; Script = { Get-ComputerInfo | Select-Object CsName, WindowsVersion, WindowsBuildLabEx, OsName, OsArchitecture, WindowsProductName, OsHardwareAbstractionLayer, Bios* | Format-List * } },
  @{ Key = "NetworkAdapterConfigs"; Description = "Network adapter configuration details"; Script = { Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object Description,Index,MACAddress,IPAddress,DefaultIPGateway,DHCPEnabled,DHCPServer,DnsServerSearchOrder | Format-List * } },
  @{ Key = "NetIPAddresses"; Description = "Current IP assignments (Get-NetIPAddress)"; Script = { try { Get-NetIPAddress -ErrorAction Stop | Format-List * } catch { "Get-NetIPAddress missing or failed: $_" } } },
  @{ Key = "NetAdapters"; Description = "Network adapter status"; Script = { try { Get-NetAdapter -ErrorAction Stop | Format-List * } catch { Get-CimInstance Win32_NetworkAdapter | Select-Object Name,NetConnectionStatus,MACAddress,Speed | Format-List * } } },
  @{ Key = "Disk_Drives"; Description = "Physical disk inventory (wmic diskdrive)"; Script = { wmic diskdrive get model,serialNumber,status,size } },
  @{ Key = "Volumes"; Description = "Volume overview (Get-Volume)"; Script = { Get-Volume | Format-Table -AutoSize } },
  @{ Key = "Disks"; Description = "Disk layout (Get-Disk)"; Script = { Get-Disk | Format-List * } },
  @{ Key = "Hotfixes"; Description = "Recent hotfixes"; Script = { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 | Format-List * } },
  @{ Key = "Programs_Reg"; Description = "Installed programs (64-bit registry)"; Script = { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion,Publisher,InstallDate | Format-Table -AutoSize } },
  @{ Key = "Programs_Reg_32"; Description = "Installed programs (32-bit registry)"; Script = { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion,Publisher,InstallDate | Format-Table -AutoSize } },
  @{ Key = "Services"; Description = "Service state overview"; Script = { Get-Service | Sort-Object Status,Name | Format-Table -AutoSize } },
  @{ Key = "Processes"; Description = "Running processes (tasklist /v)"; Script = { tasklist /v } },
  @{ Key = "Drivers"; Description = "Driver inventory (driverquery)"; Script = { driverquery /v /fo list } },
  @{ Key = "Event_System_100"; Description = "Latest 100 System event log entries"; Script = { wevtutil qe System /c:100 /f:text /rd:true } },
  @{ Key = "Event_Application_100"; Description = "Latest 100 Application event log entries"; Script = { wevtutil qe Application /c:100 /f:text /rd:true } },
  @{ Key = "Firewall"; Description = "Firewall profile status"; Script = { netsh advfirewall show allprofiles } },
  @{ Key = "FirewallRules"; Description = "Firewall rules overview"; Script = { try { Get-NetFirewallRule | Select-Object DisplayName,Direction,Action,Enabled,Profile | Format-Table -AutoSize } catch { "Get-NetFirewallRule not present" } } },
  @{ Key = "DefenderStatus"; Description = "Microsoft Defender health"; Script = { try { Get-MpComputerStatus | Format-List * } catch { "Get-MpComputerStatus not available or Defender absent" } } },
  @{ Key = "NetShares"; Description = "File shares (net share)"; Script = { net share } },
  @{ Key = "ScheduledTasks"; Description = "Scheduled task inventory"; Script = { schtasks /query /fo LIST /v } },
  @{ Key = "dsregcmd_status"; Description = "Azure AD registration status (dsregcmd /status)"; Script = { dsregcmd /status } },
  @{ Key = "Whoami"; Description = "Current user context"; Script = { whoami /all } },
  @{ Key = "Uptime"; Description = "Last boot time"; Script = { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } },
  @{ Key = "TopCPU"; Description = "Top CPU processes"; Script = { Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 | Format-Table -AutoSize } },
  @{ Key = "Memory"; Description = "Memory usage summary"; Script = { Get-CimInstance Win32_OperatingSystem | Select @{n='TotalVisibleMemoryMB';e={[math]::round($_.TotalVisibleMemorySize/1024,0)}}, @{n='FreePhysicalMemoryMB';e={[math]::round($_.FreePhysicalMemory/1024,0)}} | Format-List * } }
)

$files = @()
$activity = "Collecting system diagnostics"
$totalTasks = $capturePlan.Count
$startedTasks = 0
$completedTasks = 0

$taskQueue = New-Object System.Collections.Queue
foreach ($task in $capturePlan) {
  $taskQueue.Enqueue($task)
}

$runningJobs = @()
Write-Progress -Activity $activity -Status "Queued $totalTasks tasks" -PercentComplete 0

while ($taskQueue.Count -gt 0 -or $runningJobs.Count -gt 0) {
  while ($runningJobs.Count -lt $ThrottleLimit -and $taskQueue.Count -gt 0) {
    $nextTask = $taskQueue.Dequeue()
    $startedTasks++
    $status = "[{0}/{1}] {2}" -f $startedTasks, $totalTasks, $nextTask.Description
    Write-Host ("Starting {0}" -f $status)
    try {
      $jobInfo = Start-CollectionJob -Key $nextTask.Key -Description $nextTask.Description -Script $nextTask.Script -OutDir $reportDir
      $runningJobs += $jobInfo
    } catch {
      $errorFile = Join-Path $reportDir ("{0}.txt" -f $nextTask.Key)
      $headerLine = "===== {0} : {1} =====" -f $nextTask.Key, (Get-Date)
      Set-Content -Path $errorFile -Value @("", $headerLine, "", ("ERROR running {0} : Failed to start job. {1}" -f $nextTask.Key, $_)) -Encoding UTF8
      Write-Warning ("Failed to start {0}. See {1}" -f $nextTask.Key, $errorFile)
      $files += $errorFile
      $completedTasks++
    }
  }

  if ($runningJobs.Count -eq 0) {
    $percentComplete = if ($totalTasks -eq 0) { 100 } else { [int](($completedTasks / $totalTasks) * 100) }
    $progressStatus = "Completed {0} of {1}. Running: None" -f $completedTasks, $totalTasks
    Write-Progress -Activity $activity -Status $progressStatus -PercentComplete $percentComplete
    continue
  }

  Start-Sleep -Milliseconds 200

  $remainingJobs = @()
  foreach ($jobInfo in $runningJobs) {
    $job = $jobInfo.Job
    $state = $job.JobStateInfo.State
    $elapsed = (Get-Date) - $jobInfo.StartTime

    if (($state -eq 'Running' -or $state -eq 'NotStarted') -and $elapsed.TotalSeconds -ge $TaskTimeoutSec) {
      Write-Warning ("Timed out {0} after {1}s. See {2}" -f $jobInfo.Key, [int]$TaskTimeoutSec, $jobInfo.OutputPath)
      try { Stop-Job -Job $job -Force -ErrorAction SilentlyContinue } catch {}
      $timeoutMessage = "ERROR running {0} : Timeout after {1} sec" -f $jobInfo.Key, [int]$TaskTimeoutSec
      Set-Content -Path $jobInfo.OutputPath -Value @("", $jobInfo.HeaderLine, "", $timeoutMessage) -Encoding UTF8
      try { Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-Null } catch {}
      Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
      $files += $jobInfo.OutputPath
      $completedTasks++
      continue
    }

    if ($state -eq 'Completed' -or $state -eq 'Failed' -or $state -eq 'Stopped') {
      try { Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-Null } catch {}
      Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
      $files += $jobInfo.OutputPath
      $completedTasks++
      $duration = ((Get-Date) - $jobInfo.StartTime).TotalSeconds
      if ($state -eq 'Completed') {
        Write-Host ("Finished {0} ({1:N1}s) -> {2}" -f $jobInfo.Key, $duration, $jobInfo.OutputPath)
      } elseif ($state -eq 'Failed') {
        Write-Warning ("Finished {0} with errors ({1:N1}s). See {2}" -f $jobInfo.Key, $duration, $jobInfo.OutputPath)
      } else {
        Write-Warning ("Stopped {0} ({1:N1}s). See {2}" -f $jobInfo.Key, $duration, $jobInfo.OutputPath)
      }
      continue
    }

    $remainingJobs += $jobInfo
  }

  $runningJobs = $remainingJobs

  $percentComplete = if ($totalTasks -eq 0) { 100 } else { [int](($completedTasks / $totalTasks) * 100) }
  $runningKeys = if ($runningJobs.Count -gt 0) { ($runningJobs | ForEach-Object { $_.Key }) -join ', ' } else { 'None' }
  $progressStatus = "Completed {0} of {1}. Running: {2}" -f $completedTasks, $totalTasks, $runningKeys
  Write-Progress -Activity $activity -Status $progressStatus -PercentComplete $percentComplete
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
