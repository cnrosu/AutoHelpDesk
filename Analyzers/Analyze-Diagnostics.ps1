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

    $networkModulePath = Join-Path -Path $heuristicsPath -ChildPath 'Network/Network.ps1'
    if (Test-Path -Path $networkModulePath) {
        . $networkModulePath
    }
}
. (Join-Path -Path $PSScriptRoot -ChildPath 'SummaryBuilder.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'HtmlComposer.ps1')

$context = New-AnalyzerContext -InputFolder $InputFolder

$categories = @()
$categories += Invoke-SystemHeuristics   -Context $context
$categories += Invoke-SecurityHeuristics -Context $context
$categories += Invoke-NetworkHeuristics  -Context $context
$categories += Invoke-ADHeuristics       -Context $context
$categories += Invoke-OfficeHeuristics   -Context $context
$categories += Invoke-StorageHeuristics  -Context $context
$categories += Invoke-EventsHeuristics   -Context $context
$categories += Invoke-ServicesHeuristics -Context $context
$categories += Invoke-PrintingHeuristics -Context $context

$merged = Merge-AnalyzerResults -Categories $categories
$summary = Get-AnalyzerSummary -Context $context

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
}

$html | Out-File -FilePath $OutputPath -Encoding UTF8

[pscustomobject]@{
    HtmlPath = (Resolve-Path -Path $OutputPath).ProviderPath
    Issues   = $merged.Issues
    Normals  = $merged.Normals
    Checks   = $merged.Checks
}
