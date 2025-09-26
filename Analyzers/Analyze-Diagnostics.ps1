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
$script:progressTotal = 14
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

function Invoke-AnalyzerPhase {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock
    )

    Write-Verbose ('[{0:HH:mm:ss}] Starting phase: {1}' -f (Get-Date), $Name)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = $null
    $hadError = $false

    try {
        $result = & $ScriptBlock
    } catch {
        $hadError = $true
        Write-Verbose ('[{0:HH:mm:ss}] Phase {1} threw: {2}' -f (Get-Date), $Name, $_.Exception.Message)
        throw
    }
    finally {
        $stopwatch.Stop()
        $duration = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)

        $issueCount = 0
        $normalCount = 0
        $checkCount = 0

        foreach ($item in @($result)) {
            if (-not $item) { continue }
            if ($item.PSObject.Properties['Issues']) { $issueCount  += ($item.Issues  | Measure-Object).Count }
            if ($item.PSObject.Properties['Normals']) { $normalCount += ($item.Normals | Measure-Object).Count }
            if ($item.PSObject.Properties['Checks']) { $checkCount  += ($item.Checks  | Measure-Object).Count }
        }

        $status = if ($hadError) { 'failed' } else { 'completed' }
        Write-Verbose (
            '[{0:HH:mm:ss}] Phase {1} {2} in {3}s (issues: {4}, normals: {5}, checks: {6})' -f
            (Get-Date),
            $Name,
            $status,
            $duration,
            $issueCount,
            $normalCount,
            $checkCount
        )
    }

    return $result
}

Update-AnalyzerProgress -Status 'Initializing analyzer context'
$context = Invoke-AnalyzerPhase -Name 'Initialize context' -ScriptBlock { New-AnalyzerContext -InputFolder $InputFolder }

if ($script:CategoriesList) {
    $script:CategoriesList.Clear()
} else {
    $script:CategoriesList = [System.Collections.Generic.List[object]]::new()
}

Update-AnalyzerProgress -Status 'Loading system heuristics'
$systemCats = Invoke-AnalyzerPhase -Name 'System heuristics' -ScriptBlock { Invoke-SystemHeuristics -Context $context }
if ($systemCats) { $null = $script:CategoriesList.AddRange($systemCats) }

Update-AnalyzerProgress -Status 'Loading security heuristics'
$securityCats = Invoke-AnalyzerPhase -Name 'Security heuristics' -ScriptBlock { Invoke-SecurityHeuristics -Context $context }
if ($securityCats) { $null = $script:CategoriesList.AddRange($securityCats) }

Update-AnalyzerProgress -Status 'Loading network heuristics'
$networkCats = Invoke-AnalyzerPhase -Name 'Network heuristics' -ScriptBlock { Invoke-NetworkHeuristics -Context $context }
if ($networkCats) { $null = $script:CategoriesList.AddRange($networkCats) }

# Active Directory heuristics temporarily disabled due to known stability issues.
Update-AnalyzerProgress -Status 'Loading Microsoft 365 heuristics'
$officeCats = Invoke-AnalyzerPhase -Name 'Microsoft 365 heuristics' -ScriptBlock { Invoke-OfficeHeuristics -Context $context }
if ($officeCats) { $null = $script:CategoriesList.AddRange($officeCats) }

Update-AnalyzerProgress -Status 'Loading storage heuristics'
$storageCats = Invoke-AnalyzerPhase -Name 'Storage heuristics' -ScriptBlock { Invoke-StorageHeuristics -Context $context }
if ($storageCats) { $null = $script:CategoriesList.AddRange($storageCats) }

Update-AnalyzerProgress -Status 'Loading event log heuristics'
$eventsCats = Invoke-AnalyzerPhase -Name 'Event log heuristics' -ScriptBlock { Invoke-EventsHeuristics -Context $context }
if ($eventsCats) { $null = $script:CategoriesList.AddRange($eventsCats) }

Update-AnalyzerProgress -Status 'Loading services heuristics'
$servicesCats = Invoke-AnalyzerPhase -Name 'Services heuristics' -ScriptBlock { Invoke-ServicesHeuristics -Context $context }
if ($servicesCats) { $null = $script:CategoriesList.AddRange($servicesCats) }

Update-AnalyzerProgress -Status 'Loading printing heuristics'
$printingCats = Invoke-AnalyzerPhase -Name 'Printing heuristics' -ScriptBlock { Invoke-PrintingHeuristics -Context $context }
if ($printingCats) { $null = $script:CategoriesList.AddRange($printingCats) }

Update-AnalyzerProgress -Status 'Merging heuristic results'
$categories = $script:CategoriesList.ToArray()
$merged = Invoke-AnalyzerPhase -Name 'Merge results' -ScriptBlock { Merge-AnalyzerResults -Categories $categories }

Update-AnalyzerProgress -Status 'Building analysis summary'
$summary = Invoke-AnalyzerPhase -Name 'Build summary' -ScriptBlock { Get-AnalyzerSummary -Context $context }

Update-AnalyzerProgress -Status 'Composing HTML report'
$html = Invoke-AnalyzerPhase -Name 'Compose HTML' -ScriptBlock { New-AnalyzerHtml -Categories $categories -Summary $summary -Context $context }

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
    $cssContent = Invoke-AnalyzerPhase -Name 'Read CSS assets' -ScriptBlock {
        $resolvedCss | ForEach-Object { Get-Content -LiteralPath $_ -Raw }
    }
    Invoke-AnalyzerPhase -Name 'Bundle CSS assets' -ScriptBlock {
        Set-Content -LiteralPath $cssOutputPath -Value ($cssContent -join "`n`n") -Encoding UTF8
    } | Out-Null
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
