<#
.SYNOPSIS
  Installs the Windows components needed for the MSP PowerPack scripts.
.DESCRIPTION
  Detects the operating system role, installs the required RSAT features or capabilities, optionally enables Hyper-V
  management tools, and verifies that key modules and diagnostic utilities are available. Supports both Windows Server
  and Windows client editions.
.PARAMETER SkipHyperVTools
  Skips installation and verification of Hyper-V management components when specified.
.NOTES
  Run in an elevated PowerShell window (Run as administrator).
.EXAMPLE
  PS C:\> .\Setup-MSPPowerPackPrereqs.ps1 -SkipHyperVTools

  Installs the required RSAT tools but omits Hyper-V PowerShell features on the local machine.
#>

[CmdletBinding()]
param(
  [switch]$SkipHyperVTools
)

<#
.SYNOPSIS
  Determines whether the current PowerShell session is running with administrator privileges.
.OUTPUTS
  System.Boolean. Returns $true when the current user context belongs to the local Administrators group.
#>
function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  Write-Error "Please run this script as Administrator."
  exit 1
}

$os = Get-CimInstance Win32_OperatingSystem
# ProductType: 1=Client (Win10/11), 2=Domain Controller, 3=Server
$ptype = $os.ProductType
Write-Host ("Detected: {0}  (ProductType={1})" -f $os.Caption, $ptype)

$installed = @()

if ($ptype -eq 1) {
  # Windows 10/11 — RSAT via Features on Demand
  $caps = @(
    'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0',   # ADUC + AD PowerShell
    'Rsat.Dns.Tools~~~~0.0.1.0',                      # DNS console + DnsServer module
    'Rsat.Dhcp.Tools~~~~0.0.1.0',                     # DHCP console + DhcpServer module
    'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0',   # GPMC (handy)
    'Rsat.FileServices.Tools~~~~0.0.1.0',             # DFS mgmt consoles
    'Rsat.CertificateServices.Tools~~~~0.0.1.0'       # AD CS tools
  )
  foreach ($cap in $caps) {
    try {
      $c = Get-WindowsCapability -Online -Name $cap -ErrorAction Stop
      if ($c.State -ne 'Installed') {
        Write-Host "Installing capability: $cap"
        Add-WindowsCapability -Online -Name $cap -ErrorAction Stop | Out-Null
      } else {
        Write-Host "Already installed: $cap"
      }
      $installed += $cap
    } catch {
      Write-Warning "Could not install capability $cap : $($_.Exception.Message)"
    }
  }

  if (-not $SkipHyperVTools) {
    try {
      $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -ErrorAction Stop
      if ($hv.State -ne 'Enabled') {
        Write-Host "Enabling: Microsoft-Hyper-V-Management-PowerShell"
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart | Out-Null
      } else {
        Write-Host "Already enabled: Microsoft-Hyper-V-Management-PowerShell"
      }
    } catch {
      Write-Warning "Could not enable Hyper-V PowerShell tools: $($_.Exception.Message)"
    }
  }

} else {
  # Windows Server (including DC)
  Import-Module ServerManager

  $features = @(
    'RSAT-AD-Tools',
    'RSAT-AD-PowerShell',
    'RSAT-DNS-Server',
    'RSAT-DHCP',
    'RSAT-DFS-Mgmt-Con'
  )
  foreach ($feat in $features) {
    try {
      $f = Get-WindowsFeature $feat
      if ($f -and -not $f.Installed) {
        Write-Host "Installing feature: $feat"
        Install-WindowsFeature $feat -IncludeManagementTools -ErrorAction Stop | Out-Null
      } else {
        Write-Host "Already installed: $feat"
      }
      $installed += $feat
    } catch {
      Write-Warning "Could not install feature $feat : $($_.Exception.Message)"
    }
  }

  if (-not $SkipHyperVTools) {
    foreach ($hvFeat in @('Hyper-V-Tools','Hyper-V-PowerShell')) {
      try {
        $h = Get-WindowsFeature $hvFeat
        if ($h -and -not $h.Installed) {
          Write-Host "Installing feature: $hvFeat"
          Install-WindowsFeature $hvFeat -ErrorAction Stop | Out-Null
        } else {
          Write-Host "Already installed: $hvFeat"
        }
      } catch {
        Write-Warning "Could not install $hvFeat : $($_.Exception.Message)"
      }
    }
  }
}

Write-Host "`n=== Verifying modules ==="
$modules = @('ActiveDirectory','DnsServer','DhcpServer')
if (-not $SkipHyperVTools) { $modules += 'Hyper-V' }
foreach ($m in $modules) {
  try {
    if (Get-Module -ListAvailable -Name $m) {
      Write-Host ("[OK] Module: {0}" -f $m)
    } else {
      Write-Warning ("[MISSING] Module not found: {0}" -f $m)
    }
  } catch {
    Write-Warning ("[ERROR] Checking module {0}: {1}" -f $m, $_.Exception.Message)
  }
}

Write-Host "`n=== Verifying command-line tools ==="
$tools = @('repadmin.exe','dcdiag.exe','dfsrdiag.exe','w32tm.exe')
foreach ($t in $tools) {
  $p = Get-Command $t -ErrorAction SilentlyContinue
  if ($p) { Write-Host ("[OK] Tool: {0} ({1})" -f $t, $p.Path) } else { Write-Warning "[MISSING] Tool: $t" }
}

Write-Host "`nDone. Open a NEW elevated PowerShell window so the new modules load in the session."
