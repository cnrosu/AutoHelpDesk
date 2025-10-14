<#!
.SYNOPSIS
    Analyzer orchestrator that loads JSON artifacts, runs heuristic modules, and generates an HTML report.
.PARAMETER InputFolder
    Specifies the folder containing collector artifacts to be analyzed.
.PARAMETER OutputPath
    Optional path for the generated HTML report. When omitted, the report is written next to the input folder.
#>
using namespace System.Collections.Concurrent

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [int]$ThrottleLimit = [Math]::Max([Environment]::ProcessorCount, 2),

    [Parameter()]
    [int]$PerAnalyzerTimeoutSec = 180
)

$ErrorActionPreference = 'Stop'
Write-Verbose ("Starting analysis for input folder '{0}'." -f $InputFolder)

if (-not $PSBoundParameters.ContainsKey('OutputFolder') -or [string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path $InputFolder 'analysis'
}

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    $null = New-Item -ItemType Directory -Path $OutputFolder -Force
}

$artifactsRoot = Join-Path $OutputFolder 'Artifacts'
if (-not (Test-Path -LiteralPath $artifactsRoot)) {
    $null = New-Item -ItemType Directory -Path $artifactsRoot -Force
}

$logRoot = Join-Path $artifactsRoot 'AnalyzerLogs'
if (-not (Test-Path -LiteralPath $logRoot)) {
    $null = New-Item -ItemType Directory -Path $logRoot -Force
}

$commonModulePath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'Modules/Common.psm1'
$analyzerCommonPath = Join-Path -Path $PSScriptRoot -ChildPath 'AnalyzerCommon.ps1'
$summaryBuilderPath = Join-Path -Path $PSScriptRoot -ChildPath 'SummaryBuilder.ps1'
$htmlComposerPath   = Join-Path -Path $PSScriptRoot -ChildPath 'HtmlComposer.ps1'

if (Test-Path -Path $commonModulePath) {
    Import-Module $commonModulePath -Force -Verbose:$false
    Write-Verbose ("Imported common module from '{0}'." -f $commonModulePath)
}

. $analyzerCommonPath
. $summaryBuilderPath
. $htmlComposerPath

class AnalyzerProgress {
    [string]$Name
    [int]$Percent
    [string]$Phase
    [string]$Detail
    AnalyzerProgress([string]$n,[int]$p,[string]$ph,[string]$d) {
        $this.Name   = $n
        $this.Percent = $p
        $this.Phase   = $ph
        $this.Detail  = $d
    }
}

$queue  = [BlockingCollection[AnalyzerProgress]]::new()
$latest = [ConcurrentDictionary[string,AnalyzerProgress]]::new()
$done   = [ConcurrentDictionary[string,bool]]::new()

$reportShim = {
    param([BlockingCollection[AnalyzerProgress]]$Queue,[string]$Name)
    function Report-AnalyzerProgress {
        param([int]$Percent,[string]$Phase,[string]$Detail)
        $Queue.Add([AnalyzerProgress]::new($using:Name,$Percent,$Phase,$Detail))
    }
    Set-Alias rap Report-AnalyzerProgress -Scope Local
}

$heuristicsPath = Join-Path -Path $PSScriptRoot -ChildPath 'Heuristics'
$analyzerDefinitions = [System.Collections.Generic.List[pscustomobject]]::new()
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'System'
    ScriptPath = Join-Path $heuristicsPath 'System.ps1'
    Function = 'Invoke-SystemHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Security'
    ScriptPath = Join-Path $heuristicsPath 'Security.ps1'
    Function = 'Invoke-SecurityHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Network'
    ScriptPath = Join-Path $heuristicsPath 'Network/Network.ps1'
    Function = 'Invoke-NetworkHeuristics'
    PassInputFolder = $true
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'ActiveDirectory'
    ScriptPath = Join-Path $heuristicsPath 'AD.ps1'
    Function = 'Invoke-ADHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Office'
    ScriptPath = Join-Path $heuristicsPath 'Office.ps1'
    Function = 'Invoke-OfficeHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Intune'
    ScriptPath = Join-Path $heuristicsPath 'Intune.ps1'
    Function = 'Invoke-IntuneHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Storage'
    ScriptPath = Join-Path $heuristicsPath 'Storage.ps1'
    Function = 'Invoke-StorageHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Hardware'
    ScriptPath = Join-Path $heuristicsPath 'Hardware.ps1'
    Function = 'Invoke-HardwareHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Events'
    ScriptPath = Join-Path $heuristicsPath 'Events.ps1'
    Function = 'Invoke-EventsHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Services'
    ScriptPath = Join-Path $heuristicsPath 'Services.ps1'
    Function = 'Invoke-ServicesHeuristics'
    PassInputFolder = $false
})
$null = $analyzerDefinitions.Add([pscustomobject]@{
    Name = 'Printing'
    ScriptPath = Join-Path $heuristicsPath 'Printing.ps1'
    Function = 'Invoke-PrintingHeuristics'
    PassInputFolder = $false
})

$availableAnalyzers = $analyzerDefinitions | Where-Object { Test-Path -LiteralPath $_.ScriptPath }
if (-not $availableAnalyzers) {
    throw 'No analyzer definitions found.'
}

$pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.ApartmentState = 'MTA'
$pool.Open()

$tasks = foreach ($definition in $availableAnalyzers) {
    $name = $definition.Name
    $logPath = Join-Path $logRoot ("{0}.log" -f $name)

    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($reportShim).AddArgument($queue).AddArgument($name)

    $null = $ps.AddScript({
        param($definition,$inputFolder,$outputFolder,$logFile,$commonModule,$analyzerCommon)

        rap -Percent 5 -Phase 'Start' -Detail 'Starting'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8BOM'
        $transcriptStarted = $false
        try {
            if ($logFile) {
                try {
                    Start-Transcript -Path $logFile -Append -ErrorAction Stop | Out-Null
                    $transcriptStarted = $true
                } catch {
                    rap -Percent 15 -Phase 'Logging' -Detail 'Transcript unavailable'
                }
            }

            if ($commonModule -and (Test-Path -LiteralPath $commonModule)) {
                Import-Module $commonModule -Force -Verbose:$false
            }

            . $analyzerCommon
            . $definition.ScriptPath

            rap -Percent 20 -Phase 'Context' -Detail 'Building context'
            $context = New-AnalyzerContext -InputFolder $inputFolder

            rap -Percent 45 -Phase 'Analyzing' -Detail $definition.Function
            $invokeParams = @{ Context = $context }
            if ($definition.PassInputFolder) {
                $invokeParams['InputFolder'] = $inputFolder
            }

            $result = & $definition.Function @invokeParams

            rap -Percent 95 -Phase 'Returning' -Detail 'Sending results'
            if ($null -ne $result) {
                if ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
                    foreach ($item in $result) {
                        if ($null -ne $item) { $item }
                    }
                } else {
                    $result
                }
            }

            rap -Percent 100 -Phase 'Done' -Detail ("{0} ms" -f $sw.ElapsedMilliseconds)
        }
        catch {
            rap -Percent 100 -Phase 'Failed' -Detail $_.Exception.Message
            throw
        }
        finally {
            if ($transcriptStarted) {
                try { Stop-Transcript | Out-Null } catch {}
            }
        }
    }).AddArgument($definition).AddArgument($InputFolder).AddArgument($OutputFolder).AddArgument($logPath).AddArgument($commonModulePath).AddArgument($analyzerCommonPath)

    [pscustomobject]@{
        Name    = $name
        PS      = $ps
        Async   = $ps.BeginInvoke()
        Started = Get-Date
    }
}

$overallId = 9000
$childId = @{}
$msg = $null
while ($true) {
    $msg = $null
    while ($queue.TryTake([ref]$msg, 50)) {
        $latest[$msg.Name] = $msg
        if ($msg.Phase -in 'Done','Failed' -or $msg.Percent -ge 100) {
            $done[$msg.Name] = $true
        }
    }

    foreach ($task in $tasks) {
        if (-not $done.ContainsKey($task.Name)) {
            if ((Get-Date) -gt $task.Started.AddSeconds($PerAnalyzerTimeoutSec)) {
                try { $task.PS.Stop() | Out-Null } catch {}
                $done[$task.Name] = $true
                $latest[$task.Name] = [AnalyzerProgress]::new($task.Name,100,'Timeout',">${PerAnalyzerTimeoutSec}s, stopped")
            }
            elseif ($task.Async.IsCompleted) {
                $done[$task.Name] = $true
            }
        }
    }

    $completed = ($done.Values | Where-Object { $_ }).Count
    $total = $tasks.Count
    Write-Progress -Id $overallId -Activity 'Analyzing diagnostics' -Status ("[{0}/{1}] running..." -f $completed, $total) -PercentComplete ([int](($completed / $total) * 100))

    foreach ($kv in $latest.GetEnumerator()) {
        if (-not $childId.ContainsKey($kv.Key)) {
            $childId[$kv.Key] = ($childId.Count + 1)
        }

        $progressId = $childId[$kv.Key]
        Write-Progress -Id $progressId -ParentId $overallId -Activity $kv.Key -Status ("{0}% {1}" -f $kv.Value.Percent, $kv.Value.Phase) -CurrentOperation $kv.Value.Detail -PercentComplete ([Math]::Min([Math]::Max($kv.Value.Percent,0),100))
    }

    if ($completed -eq $total) { break }
}

Write-Progress -Id $overallId -Completed
foreach ($id in $childId.Values) { Write-Progress -Id $id -Completed }

$allCategories = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($task in $tasks) {
    try {
        $output = $task.PS.EndInvoke($task.Async)
        $count = 0
        foreach ($item in $output) {
            $count++
            $allCategories.Add($item) | Out-Null
        }
        Write-Verbose ("Analyzer '{0}' returned {1} categor(ies)." -f $task.Name, $count)
    }
    catch {
        $errors.Add([pscustomobject]@{ Analyzer = $task.Name; Error = $_.Exception.Message }) | Out-Null
        Write-Verbose ("Analyzer '{0}' failed: {1}" -f $task.Name, $_.Exception.Message)
    }
    finally {
        $task.PS.Dispose()
    }
}

$pool.Close()
$queue.Dispose()

$severityRank = @{
    critical = 0
    high     = 1
    medium   = 2
    low      = 3
    warning  = 4
    info     = 5
}

$categories = @($allCategories | Where-Object { $_ }) | Sort-Object Name
foreach ($category in $categories) {
    if ($category.Issues) {
        $issues = @($category.Issues)
        $category.Issues.Clear()
        foreach ($issue in ($issues | Sort-Object @{ Expression = {
                    $severity = if ($_.PSObject.Properties['Severity'] -and $null -ne $_.Severity) { [string]$_.Severity } else { 'info' }
                    $key = $severity.ToLowerInvariant()
                    if ($severityRank.ContainsKey($key)) { $severityRank[$key] } else { [int]::MaxValue }
                }; Ascending = $true }, Title)) {
            $category.Issues.Add($issue) | Out-Null
        }
    }

    if ($category.Normals) {
        $normals = @($category.Normals)
        $category.Normals.Clear()
        foreach ($normal in ($normals | Sort-Object Title)) {
            $category.Normals.Add($normal) | Out-Null
        }
    }

    if ($category.Checks) {
        $checks = @($category.Checks)
        $category.Checks.Clear()
        foreach ($check in ($checks | Sort-Object Name)) {
            $category.Checks.Add($check) | Out-Null
        }
    }
}

$context = New-AnalyzerContext -InputFolder $InputFolder
Write-Verbose ("Analyzer context created with {0} artifact(s)." -f $context.Artifacts.Count)

$merged = Merge-AnalyzerResults -Categories $categories
$summary = Get-AnalyzerSummary -Context $context
Write-Verbose ("Merged analyzer results include {0} issue(s) and {1} normal finding(s)." -f $merged.Issues.Count, $merged.Normals.Count)

$flatCards = [System.Collections.Generic.List[pscustomobject]]::new()
foreach ($category in $categories) {
    foreach ($issue in @($category.Issues)) {
        $flatCards.Add([pscustomobject]@{
            Category = $category.Name
            Title    = $issue.Title
            Severity = $issue.Severity
            Type     = 'Issue'
            Data     = $issue
        }) | Out-Null
    }

    foreach ($normal in @($category.Normals)) {
        $flatCards.Add([pscustomobject]@{
            Category = $category.Name
            Title    = $normal.Title
            Severity = 'info'
            Type     = 'Normal'
            Data     = $normal
        }) | Out-Null
    }

    foreach ($check in @($category.Checks)) {
        $flatCards.Add([pscustomobject]@{
            Category = $category.Name
            Title    = $check.Name
            Severity = 'info'
            Type     = 'Check'
            Data     = $check
        }) | Out-Null
    }
}

$sortedCards = $flatCards | Sort-Object Category, @{ Expression = {
        $severity = if ($_.PSObject.Properties['Severity'] -and $null -ne $_.Severity) { [string]$_.Severity } else { 'info' }
        $key = $severity.ToLowerInvariant()
        if ($severityRank.ContainsKey($key)) { $severityRank[$key] } else { [int]::MaxValue }
    }; Ascending = $true }, Title
$cardsPath = Join-Path $OutputFolder 'cards.json'
$sortedCards | ConvertTo-Json -Depth 8 | Out-File -FilePath $cardsPath -Encoding utf8

if ($errors.Count -gt 0) {
    $errorPath = Join-Path $OutputFolder 'analyzer-errors.json'
    $errors | ConvertTo-Json -Depth 6 | Out-File -FilePath $errorPath -Encoding utf8
    Write-Warning ("Some analyzers failed. See {0}." -f $errorPath)
}

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
    Cards    = $sortedCards
}
