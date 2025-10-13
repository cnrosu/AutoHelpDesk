<#Device-Report.ps1
Parent script:
  1) Runs Collectors/Collect-All.ps1 to gather JSON artifacts
  2) Locates or creates the collection folder
  3) Runs Analyzers/Analyze-Diagnostics.ps1 against it
  4) Opens the resulting HTML report
USAGE:
  PowerShell (Admin):
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Device-Report.ps1
    # or specify an existing folder to analyze:
    .\Device-Report.ps1 -InputFolder "C:\Users\Me\AppData\Local\Temp\autohelpdesk\artifacts\20250924_181518"

#>

[CmdletBinding()]
param(
  [string]$OutRoot = (Join-Path -Path $env:TEMP -ChildPath 'autohelpdesk\artifacts'),
  [string]$InputFolder # optional: analyze an existing folder without collecting
)

function Test-AnsiOutputSupport {
  try {
    if ($PSVersionTable -and $PSVersionTable.PSVersion -and $PSVersionTable.PSVersion.Major -lt 6) {
      return $false
    }

    if ($Host -and $Host.UI) {
      $property = $Host.UI.PSObject.Properties['SupportsVirtualTerminal']
      if ($property) { return [bool]$property.Value }
    }
  } catch {
    # Default to allowing ANSI when detection fails.
  }

  return $true
}

function Disable-AnsiOutput {
  try {
    if ($PSStyle -and $PSStyle.PSObject.Properties['OutputRendering']) {
      $PSStyle.OutputRendering = 'PlainText'
    }
  } catch {
    # Ignore errors if PSStyle is not available (Windows PowerShell 5, for example).
  }
}

$ansiSupported = Test-AnsiOutputSupport
if (-not $ansiSupported) {
  Disable-AnsiOutput
}

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
$repoRoot = Split-Path -Parent $here
$collectScript = Join-Path $repoRoot "Collectors/Collect-All.ps1"
$analyzeScript = Join-Path $repoRoot "Analyzers/Analyze-Diagnostics.ps1"

if (-not (Test-Path $analyzeScript)) {
  Write-Error "Analyzers/Analyze-Diagnostics.ps1 not found."
  exit 1
}

if ($InputFolder) {
  if (-not (Test-Path $InputFolder)) {
    Write-Error "InputFolder not found: $InputFolder"
    exit 1
  }
  $target = (Resolve-Path $InputFolder).ProviderPath
  Write-Host "Using existing folder: $target"
} else {
  if (-not (Test-Path $collectScript)) {
    Write-Error "Collectors/Collect-All.ps1 not found."
    exit 1
  }

  if (-not (Test-Path $OutRoot)) {
    $null = New-Item -ItemType Directory -Path $OutRoot -Force
  }

  $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $target = Join-Path $OutRoot $timestamp

  Write-Host "=== Running collection..."
  try {
    & $collectScript -OutputRoot $target 2>&1 | Tee-Object -Variable collectLog | Out-Null
  } catch {
    Write-Error "Collection failed: $_"
    exit 1
  }

  if (-not (Test-Path $target)) {
    Write-Error "Collection output not found: $target"
    exit 1
  }

  $target = (Resolve-Path $target).ProviderPath
  Write-Host "Collected into: $target"
}

Write-Host "=== Analyzing $target ..."
# Output report path captured from analyzer return value

$reportOutput = Join-Path $target 'diagnostics-report.html'

try {
  $analysisResult = & $analyzeScript -InputFolder $target -OutputPath $reportOutput
} catch {
  Write-Error "Analyzer failed: $_"
  exit 1
}

$reportPath = $null
if ($analysisResult -is [string]) {
  $reportPath = $analysisResult
} elseif ($analysisResult -and $analysisResult.PSObject.Properties['HtmlPath']) {
  $reportPath = $analysisResult.HtmlPath
}

if (-not $reportPath -or -not (Test-Path $reportPath)) {
  Write-Warning "Analyzer did not return a valid path. Attempting to locate an HTML in the folder..."
  $fallback = Get-ChildItem -Path $target -Filter *.html -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($fallback) { $reportPath = $fallback.FullName }
}

if ($reportPath -and (Test-Path $reportPath)) {
  $reportPath = (Resolve-Path $reportPath).ProviderPath
  Write-Host "Report: $reportPath"
  try { Start-Process $reportPath } catch { Write-Warning "Could not auto-open report: $_" }
} else {
  Write-Warning "No HTML report found."
}
