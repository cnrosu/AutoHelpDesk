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

# Parallel collection settings
$ThrottleLimit = 6
$TaskTimeoutSec = 60

function Start-CollectorJob {
  param(
    [Parameter(Mandatory)] [string]$Key,
    [Parameter(Mandatory)] [scriptblock]$Script,
    [Parameter(Mandatory)] [string]$OutDir,
    [string]$Description
  )

  $filePath = Join-Path $OutDir ("$Key.txt")
  $job = Start-Job -Name "collect_$Key" -ArgumentList @($Key, $Script, $OutDir) -ScriptBlock {
    param([string]$Key, [scriptblock]$ScriptBlock, [string]$OutDir)

    $file = Join-Path $OutDir ("$Key.txt")
    $header = "===== $Key : $(Get-Date) ====="
    Set-Content -Path $file -Value $header -Encoding UTF8
    '' | Out-File -FilePath $file -Encoding UTF8 -Append

    try {
      & $ScriptBlock *>&1 | Out-File -FilePath $file -Encoding UTF8 -Append
      [pscustomobject]@{ Key = $Key; Success = $true }
    } catch {
      $errorText = ($_ | Out-String).Trim()
      if (-not $errorText -and $_.Exception) {
        $errorText = $_.Exception.Message
      }
      "ERROR running $Key : $errorText" | Out-File -FilePath $file -Encoding UTF8 -Append
      [pscustomobject]@{ Key = $Key; Success = $false; Error = $errorText }
    }
  }

  [pscustomobject]@{
    Key = $Key
    Description = $Description
    Job = $job
    File = $filePath
    StartTime = Get-Date
  }
}

function Update-CollectionProgress {
  param(
    [string]$Activity,
    [int]$Completed,
    [int]$Total,
    $RunningJobs
  )

  if ($Total -le 0) {
    $percent = 100
  } else {
    $percent = [int](($Completed / $Total) * 100)
  }

  $runningKeys = @()
  if ($RunningJobs) {
    foreach ($jobInfo in $RunningJobs) {
      if ($jobInfo -and $jobInfo.Key) {
        $runningKeys += $jobInfo.Key
      }
    }
  }

  $runningSummary = if ($runningKeys.Count -gt 0) { "Running: {0}" -f ($runningKeys -join ', ') } else { 'Idle' }
  $status = "{0}/{1} complete. {2}" -f $Completed, $Total, $runningSummary
  Write-Progress -Activity $Activity -Status $status -PercentComplete $percent
}

$tasks = @(
  @{ Key = "ipconfig_all"; Description = "Detailed IP configuration (ipconfig /all)"; Script = { ipconfig /all } },
  @{ Key = "route_print"; Description = "Routing table (route print)"; Script = { route print } },
  @{ Key = "netstat_ano"; Description = "Active connections and ports (netstat -ano)"; Script = { netstat -ano } },
  @{ Key = "arp_table"; Description = "ARP cache entries (arp -a)"; Script = { arp -a } },
  @{ Key = "nslookup_google"; Description = "DNS resolution test for google.com"; Script = { nslookup google.com } },
  @{ Key = "tracert_google"; Description = "Traceroute to 8.8.8.8"; Script = { tracert -d -h 10 8.8.8.8 } },
  @{ Key = "ping_google"; Description = "Ping test to 8.8.8.8"; Script = { ping -n 4 8.8.8.8 } },
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
$totalTasks = $tasks.Count
$runningJobs = New-Object System.Collections.Generic.List[object]
$completedCount = 0
$taskIndex = 0

Update-CollectionProgress -Activity $activity -Completed $completedCount -Total $totalTasks -RunningJobs $runningJobs

while ($taskIndex -lt $totalTasks -or $runningJobs.Count -gt 0) {
  while ($taskIndex -lt $totalTasks -and $runningJobs.Count -lt $ThrottleLimit) {
    $task = $tasks[$taskIndex]
    $taskIndex++

    Write-Host ("Starting {0}... {1}" -f $task.Key, $task.Description)
    $jobInfo = Start-CollectorJob -Key $task.Key -Script $task.Script -OutDir $reportDir -Description $task.Description
    $runningJobs.Add($jobInfo)

    Update-CollectionProgress -Activity $activity -Completed $completedCount -Total $totalTasks -RunningJobs $runningJobs
  }

  if ($runningJobs.Count -eq 0) {
    continue
  }

  Start-Sleep -Milliseconds 200

  for ($idx = $runningJobs.Count - 1; $idx -ge 0; $idx--) {
    $jobInfo = $runningJobs[$idx]
    $job = $jobInfo.Job
    $state = $job.State
    $elapsed = (New-TimeSpan -Start $jobInfo.StartTime -End (Get-Date)).TotalSeconds

    if ($state -eq 'Running' -and $elapsed -ge $TaskTimeoutSec) {
      Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
      if (-not (Test-Path $jobInfo.File)) {
        $header = "===== {0} : {1} =====" -f $jobInfo.Key, (Get-Date)
        Set-Content -Path $jobInfo.File -Value $header -Encoding UTF8
        '' | Out-File -FilePath $jobInfo.File -Encoding UTF8 -Append
      }
      "ERROR running {0} : Timeout after {1} sec" -f $jobInfo.Key, $TaskTimeoutSec |
        Out-File -FilePath $jobInfo.File -Encoding UTF8 -Append
      Write-Warning ("Timed out {0} after {1} sec" -f $jobInfo.Key, $TaskTimeoutSec)
      Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
      Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
      $files += $jobInfo.File
      $completedCount++
      $runningJobs.RemoveAt($idx)
      Update-CollectionProgress -Activity $activity -Completed $completedCount -Total $totalTasks -RunningJobs $runningJobs
      continue
    }

    if ($state -eq 'Completed') {
      $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
      $jobResult = $null
      if ($null -ne $result) {
        $resultArray = @($result)
        if ($resultArray.Count -gt 0) {
          $jobResult = $resultArray[-1]
        }
      }

      $success = $true
      $errorMessage = $null
      if ($jobResult -and ($jobResult | Get-Member -Name Success -ErrorAction SilentlyContinue)) {
        $success = [bool]$jobResult.Success
        if (-not $success -and ($jobResult | Get-Member -Name Error -ErrorAction SilentlyContinue)) {
          $errorMessage = $jobResult.Error
        }
      }

      if ($success) {
        Write-Host ("Finished {0} ({1:N1}s)" -f $jobInfo.Key, $elapsed)
      } else {
        if (-not $errorMessage) {
          $errorMessage = "Unknown error"
        }
        Write-Warning ("Failed {0}: {1}" -f $jobInfo.Key, $errorMessage)
        if (-not (Select-String -Path $jobInfo.File -Pattern 'ERROR running' -SimpleMatch -Quiet -ErrorAction SilentlyContinue)) {
          "ERROR running {0} : {1}" -f $jobInfo.Key, $errorMessage |
            Out-File -FilePath $jobInfo.File -Encoding UTF8 -Append
        }
      }

      Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
      $files += $jobInfo.File
      $completedCount++
      $runningJobs.RemoveAt($idx)
      Update-CollectionProgress -Activity $activity -Completed $completedCount -Total $totalTasks -RunningJobs $runningJobs
      continue
    }

    if ($state -eq 'Failed' -or $state -eq 'Stopped') {
      $reason = $null
      if ($job.ChildJobs -and $job.ChildJobs.Count -gt 0) {
        $reason = $job.ChildJobs[0].JobStateInfo.Reason
      } else {
        $reason = $job.JobStateInfo.Reason
      }
      $reasonText = if ($reason) { $reason.ToString() } else { "Job $state" }
      if (-not (Test-Path $jobInfo.File)) {
        $header = "===== {0} : {1} =====" -f $jobInfo.Key, (Get-Date)
        Set-Content -Path $jobInfo.File -Value $header -Encoding UTF8
        '' | Out-File -FilePath $jobInfo.File -Encoding UTF8 -Append
      }
      if (-not (Select-String -Path $jobInfo.File -Pattern 'ERROR running' -SimpleMatch -Quiet -ErrorAction SilentlyContinue)) {
        "ERROR running {0} : {1}" -f $jobInfo.Key, $reasonText |
          Out-File -FilePath $jobInfo.File -Encoding UTF8 -Append
      }
      Write-Warning ("Failed {0}: {1}" -f $jobInfo.Key, $reasonText)
      Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
      Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
      $files += $jobInfo.File
      $completedCount++
      $runningJobs.RemoveAt($idx)
      Update-CollectionProgress -Activity $activity -Completed $completedCount -Total $totalTasks -RunningJobs $runningJobs
    }
  }
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
