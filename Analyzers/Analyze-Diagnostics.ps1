<#!
.SYNOPSIS
    Analyzer orchestrator that loads JSON artifacts, runs heuristic modules, and generates an HTML report.
.PARAMETER InputFolder
    Specifies the folder containing collector artifacts to be analyzed.
.PARAMETER OutputPath
    Optional path for the generated HTML report. When omitted, the report is written next to the input folder.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$commonModulePath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'Modules/Common.psm1'
if (Test-Path -Path $commonModulePath) {
    Import-Module $commonModulePath -Force
}

. (Join-Path -Path $PSScriptRoot -ChildPath 'AnalyzerCommon.ps1')
$heuristicsPath = Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics'
if (Test-Path -Path $heuristicsPath) {
    Get-ChildItem -Path $heuristicsPath -Filter '*.ps1' -File | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}
. (Join-Path -Path $PSScriptRoot -ChildPath 'SummaryBuilder.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'HtmlComposer.ps1')

$script:progressActivity = 'Running diagnostics analysis'
$script:progressTotal = 15
$script:progressIndex = 0

function Update-AnalyzerProgress {
    param(
        [Parameter(Mandatory)]
        [string]$Status,

        [int]$Advance = 1
    )

    $script:progressIndex += $Advance
    $percentComplete = 0
    if ($script:progressTotal -gt 0) {
        $percentComplete = [math]::Min([int](($script:progressIndex / [double]$script:progressTotal) * 100), 100)
    }

    Write-Progress -Activity $script:progressActivity -Status $Status -PercentComplete $percentComplete
    Write-Verbose ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $Status)
}

Update-AnalyzerProgress -Status 'Initializing analyzer context'
$context = New-AnalyzerContext -InputFolder $InputFolder

$categories = @()

Update-AnalyzerProgress -Status 'Loading system heuristics'
$categories += Invoke-SystemHeuristics   -Context $context

Update-AnalyzerProgress -Status 'Loading security heuristics'
$categories += Invoke-SecurityHeuristics -Context $context

Update-AnalyzerProgress -Status 'Loading network heuristics'
$categories += Invoke-NetworkHeuristics  -Context $context

Update-AnalyzerProgress -Status 'Loading Active Directory heuristics'
$categories += Invoke-ADHeuristics       -Context $context

Update-AnalyzerProgress -Status 'Loading Microsoft 365 heuristics'
$categories += Invoke-OfficeHeuristics   -Context $context

Update-AnalyzerProgress -Status 'Loading storage heuristics'
$categories += Invoke-StorageHeuristics  -Context $context

Update-AnalyzerProgress -Status 'Loading event log heuristics'
$categories += Invoke-EventsHeuristics   -Context $context

Update-AnalyzerProgress -Status 'Loading services heuristics'
$categories += Invoke-ServicesHeuristics -Context $context

Update-AnalyzerProgress -Status 'Loading printing heuristics'
$categories += Invoke-PrintingHeuristics -Context $context

Update-AnalyzerProgress -Status 'Merging heuristic results'
$merged = Merge-AnalyzerResults -Categories $categories

Update-AnalyzerProgress -Status 'Building analysis summary'
$summary = Get-AnalyzerSummary -Context $context

Update-AnalyzerProgress -Status 'Composing HTML report'
$html = New-AnalyzerHtml -Categories $categories -Summary $summary -Context $context

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $InputFolder -ChildPath 'diagnostics-report.html'
}

$directory = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $directory)) {
    $null = New-Item -Path $directory -ItemType Directory -Force
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$autoL1Path = Join-Path -Path $repoRoot -ChildPath 'AutoL1'

$cssSources = @(
    Join-Path -Path $repoRoot -ChildPath 'styles/base.css'
    Join-Path -Path $repoRoot -ChildPath 'styles/layout.css'
    Join-Path -Path $autoL1Path -ChildPath 'styles/device-health-report.css'
)

$resolvedCss = @()
Update-AnalyzerProgress -Status 'Preparing report styles'
foreach ($source in $cssSources) {
    if (Test-Path -LiteralPath $source) {
        $resolvedCss += (Resolve-Path -LiteralPath $source).ProviderPath
    }
}

if ($resolvedCss.Count -gt 0) {
    $cssOutputDir = Join-Path -Path $directory -ChildPath 'styles'
    if (-not (Test-Path -LiteralPath $cssOutputDir)) {
        $null = New-Item -Path $cssOutputDir -ItemType Directory -Force
    }

    $cssOutputPath = Join-Path -Path $cssOutputDir -ChildPath 'device-health-report.css'
    $cssContent = $resolvedCss | ForEach-Object { Get-Content -LiteralPath $_ -Raw }
    Set-Content -LiteralPath $cssOutputPath -Value ($cssContent -join "`n`n") -Encoding UTF8
    Write-Verbose ('[{0:HH:mm:ss}] Report styles bundled to {1}' -f (Get-Date), $cssOutputPath)
} else {
    Write-Verbose ('[{0:HH:mm:ss}] No report styles found to bundle' -f (Get-Date))
}

Update-AnalyzerProgress -Status 'Writing analysis report to disk'
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Progress -Activity $script:progressActivity -Completed -Status 'Analysis complete'
Write-Verbose ('[{0:HH:mm:ss}] Analysis complete. Output: {1}' -f (Get-Date), $OutputPath)

[pscustomobject]@{
    HtmlPath = (Resolve-Path -Path $OutputPath).ProviderPath
    Issues   = $merged.Issues
    Normals  = $merged.Normals
    Checks   = $merged.Checks
}
