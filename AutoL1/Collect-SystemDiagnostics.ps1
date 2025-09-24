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

# Simple helper to run a command and write output
function Save-Output([string]$name, [scriptblock]$action) {
  $file = Join-Path $reportDir ("$name.txt")
  $sep = "`n===== $name : $(Get-Date) =====`n"
  Add-Content -Path $file -Value $sep
  try {
    & $action *>&1 | Out-File -FilePath $file -Encoding UTF8 -Append
  } catch {
    "ERROR running $name : $_" | Out-File -FilePath $file -Append
  }
  return $file
}

# Commands to capture
$files = @()

$files += Save-Output "ipconfig_all" { ipconfig /all }
$files += Save-Output "route_print" { route print }
$files += Save-Output "netstat_ano" { netstat -ano }
$files += Save-Output "arp_table" { arp -a }
$files += Save-Output "nslookup_google" { nslookup google.com }
$files += Save-Output "tracert_google" { tracert -d -h 10 8.8.8.8 }
$files += Save-Output "ping_google" { ping -n 4 8.8.8.8 }
$files += Save-Output "systeminfo" { systeminfo }

# WMI / CIM queries (more structured)
$files += Save-Output "OS_CIM" { Get-CimInstance Win32_OperatingSystem | Format-List * }
$files += Save-Output "ComputerInfo" { Get-ComputerInfo | Select-Object CsName, WindowsVersion, WindowsBuildLabEx, OsName, OsArchitecture, WindowsProductName, OsHardwareAbstractionLayer, Bios* | Format-List * }

$files += Save-Output "NetworkAdapterConfigs" { Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object Description,Index,MACAddress,IPAddress,DefaultIPGateway,DHCPEnabled,DHCPServer,DnsServerSearchOrder | Format-List * }
$files += Save-Output "NetIPAddresses" { try { Get-NetIPAddress -ErrorAction Stop | Format-List * } catch { "Get-NetIPAddress missing or failed: $_" } }
$files += Save-Output "NetAdapters" { try { Get-NetAdapter -ErrorAction Stop | Format-List * } catch { Get-CimInstance Win32_NetworkAdapter | Select-Object Name,NetConnectionStatus,MACAddress,Speed | Format-List * } }

$files += Save-Output "Disk_Drives" { wmic diskdrive get model,serialNumber,status,size }
$files += Save-Output "Volumes" { Get-Volume | Format-Table -AutoSize }
$files += Save-Output "Disks" { Get-Disk | Format-List * }

$files += Save-Output "Hotfixes" { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 | Format-List * }
$files += Save-Output "Programs_Reg" { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion,Publisher,InstallDate | Format-Table -AutoSize }
$files += Save-Output "Programs_Reg_32" { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion,Publisher,InstallDate | Format-Table -AutoSize }

$files += Save-Output "Services" { Get-Service | Sort-Object Status,Name | Format-Table -AutoSize }
$files += Save-Output "Processes" { tasklist /v }
$files += Save-Output "Drivers" { driverquery /v /fo list }

$files += Save-Output "Event_System_100" { wevtutil qe System /c:100 /f:text /rd:true }
$files += Save-Output "Event_Application_100" { wevtutil qe Application /c:100 /f:text /rd:true }

$files += Save-Output "Firewall" { netsh advfirewall show allprofiles }
$files += Save-Output "FirewallRules" { try { Get-NetFirewallRule | Select-Object DisplayName,Direction,Action,Enabled,Profile | Format-Table -AutoSize } catch { "Get-NetFirewallRule not present" } }

$files += Save-Output "DefenderStatus" { try { Get-MpComputerStatus | Format-List * } catch { "Get-MpComputerStatus not available or Defender absent" } }

$files += Save-Output "NetShares" { net share }
$files += Save-Output "ScheduledTasks" { schtasks /query /fo LIST /v }

$files += Save-Output "Whoami" { whoami /all }
$files += Save-Output "Uptime" { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }

# quick perf snapshot
$files += Save-Output "TopCPU" { Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 | Format-Table -AutoSize }
$files += Save-Output "Memory" { Get-CimInstance Win32_OperatingSystem | Select @{n='TotalVisibleMemoryMB';e={[math]::round($_.TotalVisibleMemorySize/1024,0)}}, @{n='FreePhysicalMemoryMB';e={[math]::round($_.FreePhysicalMemory/1024,0)}} | Format-List * }

# Save copies of the core raw outputs too
Copy-Item -Path $files -Destination $reportDir -Force -ErrorAction SilentlyContinue

# Simple parser: extract key fields from ipconfig /all
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

# Basic HTML report
if (-not $NoHtml) {
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
}

Write-Host "All raw files saved to: $reportDir"
