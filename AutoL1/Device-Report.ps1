<#
.SYNOPSIS
  Coordinates collection and analysis to produce an AutoHelpDesk device health report.
.DESCRIPTION
  Ensures the session is elevated, runs Collect-SystemDiagnostics.ps1 when no existing folder is provided, chooses the
  most recent collection directory, invokes Analyze-Diagnostics.ps1, and opens the resulting HTML report for review.
.PARAMETER OutRoot
  Specifies the root folder where new diagnostic collections should be created. Defaults to the desktop DiagReports
  directory for the current user.
.PARAMETER InputFolder
  Provides the path to an existing diagnostics folder to analyze without running collection.
.EXAMPLE
  PS C:\> .\Device-Report.ps1

  Collects diagnostics into the default location, analyzes the results, and opens the generated HTML report.
.EXAMPLE
  PS C:\> .\Device-Report.ps1 -InputFolder 'C:\Reports\Diag\20250101_103000'

  Skips new collection and analyzes the specified folder.
#>

[CmdletBinding()]
param(
  [string]$OutRoot = "$env:USERPROFILE\Desktop\DiagReports",
  [string]$InputFolder # optional: analyze an existing folder without collecting
)

<#
.SYNOPSIS
  Ensures the script is running with administrator privileges and stops execution when it is not.
.DESCRIPTION
  Checks the current security principal for membership in the local Administrators group and terminates the script with
  an error message when elevation is missing.
.OUTPUTS
  None. Throws a terminating error when the session is not elevated.
#>
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

# Compute health scores if available
if ($Checks) { $Scores = Get-HealthScores -Checks $Checks } else { $Scores = @{} }
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
