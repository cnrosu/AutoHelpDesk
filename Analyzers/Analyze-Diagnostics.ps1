$global:EnableDiag = ($env:ANALYZER_DEBUG -eq '1')
$EnableDiag = $global:EnableDiag
if ($EnableDiag) { $VerbosePreference = 'Continue' }

trap {
    try { if ($EnableDiag) { Get-PSCallStack | Format-List -Force | Out-Host } } catch {}
    throw
}

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

Start-Phase 'Collecting'
Update-AnalyzerProgress -Status 'Initializing analyzer context'
$context = Invoke-AnalyzerPhase -Name 'Initialize context' -ScriptBlock {
    With-Timing 'Initialize context' {
        New-AnalyzerContext -InputFolder $InputFolder
    }
}
if ($EnableDiag) {
    $contextType = if ($null -eq $context) { '<null>' } else { $context.GetType().FullName }
    if ($null -eq $context -or -not $context.PSObject.Properties['Artifacts']) {
        throw "Context missing Artifacts (got: $contextType)"
    }
}
End-Phase 'Collecting'

if ($script:CategoriesList) {
    $script:CategoriesList.Clear()
} else {
    $script:CategoriesList = [System.Collections.Generic.List[object]]::new()
}

function Add-AnalyzerCategories {
    param(
        [Parameter(ValueFromPipeline)]
        [object]$InputObject
    )

    process {
        if (-not $InputObject) { return }

        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
            foreach ($item in $InputObject) {
                if ($null -ne $item) {
                    $null = $script:CategoriesList.Add($item)
                }
            }
        } else {
            $null = $script:CategoriesList.Add($InputObject)
        }
    }
}

function Invoke-Safe {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Block
    )

    try {
        return & $Block
    } catch {
        if ($EnableDiag) {
            Write-Warning ("[{0}] failed: {1}" -f $Name,$_.Exception.Message)
            try { Get-PSCallStack | Format-List -Force | Out-Host } catch {}
        }
        $category = New-CategoryResult -Name "$Name diagnostics"
        Add-CategoryIssue -CategoryResult $category -Severity 'medium' -Title "$Name failed" -Evidence $_.ToString() -Subcategory 'Internal Error'
        return ,$category
    }
}

$previousErrorPreference = $ErrorActionPreference
$previousMaximumFunctionCount = $MaximumFunctionCount
if ($EnableDiag) {
    $ErrorActionPreference = 'Continue'
    $MaximumFunctionCount = 8192
}

Start-Phase 'Analyzing'

Update-AnalyzerProgress -Status 'Loading system heuristics'
Mark 'Loading System heuristics'
$systemCats = Invoke-AnalyzerPhase -Name 'System heuristics' -ScriptBlock {
    Invoke-Safe 'System heuristics' {
        With-Timing 'System heuristics' { Invoke-SystemHeuristics -Context $context }
    }
}
CountOf 'System categories' $systemCats
Add-AnalyzerCategories -InputObject $systemCats

Update-AnalyzerProgress -Status 'Loading security heuristics'
Mark 'Loading Security heuristics'
$securityCats = Invoke-AnalyzerPhase -Name 'Security heuristics' -ScriptBlock {
    Invoke-Safe 'Security heuristics' {
        With-Timing 'Security heuristics' { Invoke-SecurityHeuristics -Context $context }
    }
}
CountOf 'Security categories' $securityCats
Add-AnalyzerCategories -InputObject $securityCats

Update-AnalyzerProgress -Status 'Loading network heuristics'
Mark 'Loading Network heuristics'
$networkCats = Invoke-AnalyzerPhase -Name 'Network heuristics' -ScriptBlock {
    Invoke-Safe 'Network heuristics' {
        With-Timing 'Network heuristics' { Invoke-NetworkHeuristics -Context $context }
    }
}
CountOf 'Network categories' $networkCats
Add-AnalyzerCategories -InputObject $networkCats

Update-AnalyzerProgress -Status 'Loading Active Directory heuristics'
Mark 'Loading Active Directory heuristics'
$adCats = Invoke-AnalyzerPhase -Name 'Active Directory heuristics' -ScriptBlock {
    Invoke-Safe 'AD heuristics' {
        With-Timing 'AD heuristics' { Invoke-ADHeuristics -Context $context }
    }
}
CountOf 'AD categories' $adCats
Add-AnalyzerCategories -InputObject $adCats

Update-AnalyzerProgress -Status 'Loading Microsoft 365 heuristics'
Mark 'Loading Microsoft 365 heuristics'
$officeCats = Invoke-AnalyzerPhase -Name 'Microsoft 365 heuristics' -ScriptBlock {
    Invoke-Safe 'Microsoft 365 heuristics' {
        With-Timing 'Microsoft 365 heuristics' { Invoke-OfficeHeuristics -Context $context }
    }
}
CountOf 'Microsoft 365 categories' $officeCats
Add-AnalyzerCategories -InputObject $officeCats

Update-AnalyzerProgress -Status 'Loading storage heuristics'
Mark 'Loading Storage heuristics'
$storageCats = Invoke-AnalyzerPhase -Name 'Storage heuristics' -ScriptBlock {
    Invoke-Safe 'Storage heuristics' {
        With-Timing 'Storage heuristics' { Invoke-StorageHeuristics -Context $context }
    }
}
CountOf 'Storage categories' $storageCats
Add-AnalyzerCategories -InputObject $storageCats

Update-AnalyzerProgress -Status 'Loading event log heuristics'
Mark 'Loading Event log heuristics'
$eventsCats = Invoke-AnalyzerPhase -Name 'Event log heuristics' -ScriptBlock {
    Invoke-Safe 'Event log heuristics' {
        With-Timing 'Event log heuristics' { Invoke-EventsHeuristics -Context $context }
    }
}
CountOf 'Event log categories' $eventsCats
Add-AnalyzerCategories -InputObject $eventsCats

Update-AnalyzerProgress -Status 'Loading services heuristics'
Mark 'Loading Services heuristics'
$servicesCats = Invoke-AnalyzerPhase -Name 'Services heuristics' -ScriptBlock {
    Invoke-Safe 'Services heuristics' {
        With-Timing 'Services heuristics' { Invoke-ServicesHeuristics -Context $context }
    }
}
CountOf 'Services categories' $servicesCats
Add-AnalyzerCategories -InputObject $servicesCats

Update-AnalyzerProgress -Status 'Loading printing heuristics'
Mark 'Loading Printing heuristics'
$printingCats = Invoke-AnalyzerPhase -Name 'Printing heuristics' -ScriptBlock {
    Invoke-Safe 'Printing heuristics' {
        With-Timing 'Printing heuristics' { Invoke-PrintingHeuristics -Context $context }
    }
}
CountOf 'Printing categories' $printingCats
Add-AnalyzerCategories -InputObject $printingCats

$categories = $script:CategoriesList.ToArray()
CountOf 'Analyzing: categories aggregated' $categories
if ($EnableDiag -and $categories.Count -gt 20000) {
    Write-Verbose ("[WARN] Large input ({0}) in {1}" -f $categories.Count,$MyInvocation.MyCommand)
}

Update-AnalyzerProgress -Status 'Merging heuristic results'
$merged = Invoke-AnalyzerPhase -Name 'Merge results' -ScriptBlock {
    With-Timing 'Merge all categories' {
        Merge-AnalyzerResults -Categories $categories
    }
}

Update-AnalyzerProgress -Status 'Building analysis summary'
Mark 'Building analysis summary'
$summary = Invoke-AnalyzerPhase -Name 'Build summary' -ScriptBlock {
    With-Timing 'Build summary' { Get-AnalyzerSummary -Context $context }
}

End-Phase 'Analyzing'
$ErrorActionPreference = $previousErrorPreference
if ($EnableDiag -and $null -ne $previousMaximumFunctionCount) { $MaximumFunctionCount = $previousMaximumFunctionCount }

$htmlErrorPreference = $ErrorActionPreference
if ($EnableDiag) { $ErrorActionPreference = 'Continue' }

Start-Phase 'HTML Compose'
Update-AnalyzerProgress -Status 'Composing HTML report'
Mark 'HTML Compose: build cards'
$cards = With-Timing 'Build issue cards' {
    Convert-CategoriesToCards -Categories $categories
}
CountOf 'Cards' $cards.All

Mark 'HTML Compose: render report'
$html = Invoke-AnalyzerPhase -Name 'Compose HTML' -ScriptBlock {
    With-Timing 'Render HTML' {
        New-AnalyzerHtml -Cards $cards -Summary $summary -Context $context -Categories $categories
    }
}
End-Phase 'HTML Compose'
if ($EnableDiag) { $ErrorActionPreference = $htmlErrorPreference }

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
