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
Write-Verbose ("Starting analysis for input folder '{0}'." -f $InputFolder)

$commonModulePath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'Modules/Common.psm1'
if (Test-Path -Path $commonModulePath) {
    Import-Module $commonModulePath -Force -Verbose:$false
    Write-Verbose ("Imported common module from '{0}'." -f $commonModulePath)
}

. (Join-Path -Path $PSScriptRoot -ChildPath 'AnalyzerCommon.ps1')
$heuristicsPath = Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics'
if (Test-Path -Path $heuristicsPath) {
    Write-Verbose ("Loading heuristic scripts from '{0}'." -f $heuristicsPath)
    $heuristicScripts = Get-ChildItem -Path $heuristicsPath -Filter '*.ps1' -File | Sort-Object Name
    foreach ($script in $heuristicScripts) {
        . $script.FullName
        Write-Verbose ("Loaded heuristic script '{0}'." -f $script.FullName)
    }

    $networkModulePath = Join-Path -Path $heuristicsPath -ChildPath 'Network/Network.ps1'
    if (Test-Path -Path $networkModulePath) {
        . $networkModulePath
        Write-Verbose ("Loaded network heuristic module '{0}'." -f $networkModulePath)
    }
}
. (Join-Path -Path $PSScriptRoot -ChildPath 'SummaryBuilder.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'HtmlComposer.ps1')

$context = New-AnalyzerContext -InputFolder $InputFolder
Write-Verbose ("Analyzer context created with {0} artifact(s)." -f $context.Artifacts.Count)

$categoriesList = [System.Collections.Generic.List[object]]::new()
$systemCategories = Invoke-SystemHeuristics   -Context $context
if ($systemCategories) { foreach ($item in @($systemCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'System heuristics completed.'
$securityCategories = Invoke-SecurityHeuristics -Context $context
if ($securityCategories) { foreach ($item in @($securityCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Security heuristics completed.'
$networkCategories = Invoke-NetworkHeuristics  -Context $context -InputFolder $InputFolder
if ($networkCategories) { foreach ($item in @($networkCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Network heuristics completed.'
$adCategories = Invoke-ADHeuristics       -Context $context
if ($adCategories) { foreach ($item in @($adCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Active Directory heuristics completed.'
$officeCategories = Invoke-OfficeHeuristics   -Context $context
if ($officeCategories) { foreach ($item in @($officeCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Office heuristics completed.'
$intuneCategories = Invoke-IntuneHeuristics -Context $context
if ($intuneCategories) { foreach ($item in @($intuneCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Intune heuristics completed.'
$storageCategories = Invoke-StorageHeuristics  -Context $context
if ($storageCategories) { foreach ($item in @($storageCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Storage heuristics completed.'
$hardwareCategories = Invoke-HardwareHeuristics -Context $context
if ($hardwareCategories) { foreach ($item in @($hardwareCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Hardware heuristics completed.'
$eventsCategories = Invoke-EventsHeuristics   -Context $context
if ($eventsCategories) { foreach ($item in @($eventsCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Events heuristics completed.'
$servicesCategories = Invoke-ServicesHeuristics -Context $context
if ($servicesCategories) { foreach ($item in @($servicesCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Services heuristics completed.'
$printingCategories = Invoke-PrintingHeuristics -Context $context
if ($printingCategories) { foreach ($item in @($printingCategories)) { $categoriesList.Add($item) } }
Write-Verbose 'Printing heuristics completed.'

$categories = $categoriesList.ToArray()

$merged = Merge-AnalyzerResults -Categories $categories
$summary = Get-AnalyzerSummary -Context $context
Write-Verbose ("Merged analyzer results include {0} issue(s) and {1} normal finding(s)." -f $merged.Issues.Count, $merged.Normals.Count)

$categoryCount = if ($categories) { ($categories | Measure-Object).Count } else { 0 }
Write-HtmlDebug -Stage 'Orchestrator' -Message 'Invoking New-AnalyzerHtml.' -Data @{ Categories = $categoryCount; Issues = $merged.Issues.Count; Normals = $merged.Normals.Count }
$html = New-AnalyzerHtml -Categories $categories -Summary $summary -Context $context
Write-HtmlDebug -Stage 'Orchestrator' -Message 'New-AnalyzerHtml completed.' -Data @{ Length = $html.Length }
Write-Verbose 'HTML report composed.'

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $InputFolder -ChildPath 'diagnostics-report.html'
}

$directory = Split-Path -Path $OutputPath -Parent
if ([string]::IsNullOrWhiteSpace($directory)) {
    $directory = (Get-Location).ProviderPath
}

if (-not (Test-Path -Path $directory)) {
    $null = New-Item -Path $directory -ItemType Directory -Force
    Write-Verbose ("Created output directory '{0}'." -f $directory)
}

$repoRoot = Split-Path $PSScriptRoot -Parent

$cssSources = @(
    Join-Path -Path $repoRoot -ChildPath 'styles/base.css'
    Join-Path -Path $repoRoot -ChildPath 'styles/layout.css'
    Join-Path -Path $repoRoot -ChildPath 'styles/device-health-report.css'
)

$resolvedCss = [System.Collections.Generic.List[string]]::new()
foreach ($source in $cssSources) {
    if (Test-Path -LiteralPath $source) {
        $resolvedCss.Add((Resolve-Path -LiteralPath $source).ProviderPath)
        Write-Verbose ("Resolved CSS source '{0}'." -f $source)
    }
}

if ($resolvedCss.Count -gt 0) {
    $cssOutputDir = Join-Path -Path $directory -ChildPath 'styles'
    if (-not (Test-Path -LiteralPath $cssOutputDir)) {
        $null = New-Item -Path $cssOutputDir -ItemType Directory -Force
        Write-Verbose ("Created CSS output directory '{0}'." -f $cssOutputDir)
    }

    $cssOutputPath = Join-Path -Path $cssOutputDir -ChildPath 'device-health-report.css'
    $cssContent = [System.Collections.Generic.List[string]]::new()
    foreach ($cssPath in $resolvedCss) {
        $null = $cssContent.Add((Get-Content -LiteralPath $cssPath -Raw))
    }

    Set-Content -LiteralPath $cssOutputPath -Value ($cssContent -join "`n`n") -Encoding UTF8
    Write-Verbose ("Combined CSS written to '{0}'." -f $cssOutputPath)
}

Write-HtmlDebug -Stage 'Orchestrator' -Message 'Writing HTML report to disk.' -Data @{ Path = $OutputPath }
$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-HtmlDebug -Stage 'Orchestrator' -Message 'HTML report write complete.' -Data @{ Path = $OutputPath }
Write-Verbose ("HTML report written to '{0}'." -f $OutputPath)

[pscustomobject]@{
    HtmlPath = (Resolve-Path -Path $OutputPath).ProviderPath
    Issues   = $merged.Issues
    Normals  = $merged.Normals
    Checks   = $merged.Checks
}
