<# 
Device-Report.ps1
Parent script: 
  1) Runs Collect-SystemDiagnostics.ps1 to gather outputs
  2) Locates the newest collection folder
  3) Runs Analyze-Diagnostics.ps1 against it
  4) Opens the resulting HTML report
USAGE:
  PowerShell (Admin):
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Device-Report.ps1
    # or specify an existing folder to analyze:
    .\Device-Report.ps1 -InputFolder "C:\Users\Me\Desktop\DiagReports\20250924_181518"
#>

[CmdletBinding()]
param(
  [string]$OutRoot = "$env:USERPROFILE\Desktop\DiagReports",
  [string]$InputFolder # optional: analyze an existing folder without collecting
)

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script elevated (Run as Administrator)."
    exit 1
  }
}
Assert-Admin

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$collectScript = Join-Path $here "Collect-SystemDiagnostics.ps1"
$analyzeScript = Join-Path $here "Analyze-Diagnostics.ps1"

if (-not (Test-Path $analyzeScript)) {
  Write-Error "Analyze-Diagnostics.ps1 not found next to Device-Report.ps1."
  exit 1
}

if ($InputFolder) {
  if (-not (Test-Path $InputFolder)) {
    Write-Error "InputFolder not found: $InputFolder"
    exit 1
  }
  $target = (Resolve-Path $InputFolder).Path
  Write-Host "Using existing folder: $target"
} else {
  if (-not (Test-Path $collectScript)) {
    Write-Error "Collect-SystemDiagnostics.ps1 not found next to Device-Report.ps1."
    exit 1
  }

  Write-Host "=== Running collection..."
  & $collectScript -OutRoot $OutRoot 2>&1 | Tee-Object -Variable collectLog | Out-Null

  if (-not (Test-Path $OutRoot)) {
    Write-Error "OutRoot not created. Collection may have failed."
    exit 1
  }

  # Pick newest timestamped subfolder
  $latest = Get-ChildItem -Path $OutRoot -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $latest) {
    Write-Error "No subfolders found in $OutRoot after collection."
    exit 1
  }
  $target = $latest.FullName
  Write-Host "Collected into: $target"
}

Write-Host "=== Analyzing $target ..."
# Output report path captured from analyzer stdout
$reportPath = & $analyzeScript -InputFolder $target
if (-not $reportPath -or -not (Test-Path $reportPath)) {
  Write-Warning "Analyzer did not return a valid path. Attempting to locate an HTML in the folder..."
  $fallback = Get-ChildItem -Path $target -Filter *.html -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($fallback) { $reportPath = $fallback.FullName }
}

if ($reportPath -and (Test-Path $reportPath)) {
  Write-Host "Report: $reportPath"
  try { Start-Process $reportPath } catch { Write-Warning "Could not auto-open report: $_" }
} else {
  Write-Warning "No HTML report found."
}
