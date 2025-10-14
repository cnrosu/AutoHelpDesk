<#!
.SYNOPSIS
    Runs all collector scripts and writes JSON output per area.
.DESCRIPTION
    Discovers collector scripts under the Collectors directory (excluding Collect-All.ps1 and shared helpers),
    executes each script, and groups the JSON artifacts by area (Security/System/Network/Office/etc.).
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputRoot = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath 'output'),

    [Parameter()]
    [int]$ThrottleLimit = [math]::Max([System.Environment]::ProcessorCount, 1)
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'CollectorCommon.ps1')

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$concurrencyModulePath = Join-Path -Path $repoRoot -ChildPath 'Modules/Concurrency.psm1'
if (-not (Test-Path -LiteralPath $concurrencyModulePath)) {
    throw "Concurrency module not found at '$concurrencyModulePath'."
}

Import-Module $concurrencyModulePath -Force -Verbose:$false

function Test-AnsiOutputSupport {
    try {
        if ($PSVersionTable -and $PSVersionTable.PSVersion -and $PSVersionTable.PSVersion.Major -lt 6) {
            return $false
        }

        if ($Host -and $Host.UI) {
            $property = $Host.UI.PSObject.Properties['SupportsVirtualTerminal']
            if ($property) {
                return [bool]$property.Value
            }
        }
    } catch {
        # Fall back to assuming support when the environment cannot be queried.
    }

    return $true
}

function Disable-AnsiOutput {
    try {
        if ($PSStyle -and $PSStyle.PSObject.Properties['OutputRendering']) {
            $PSStyle.OutputRendering = 'PlainText'
        }
    } catch {
        # Older PowerShell versions do not expose PSStyle – ignore errors here.
    }
}

$script:durationFormatCulture = [System.Globalization.CultureInfo]::InvariantCulture

function Format-CollectorDuration {
    param(
        [Parameter(Mandatory)]
        [TimeSpan]$Duration
    )

    if ($Duration.TotalSeconds -lt 1) {
        $milliseconds = [math]::Round($Duration.TotalMilliseconds)
        return [string]::Format($script:durationFormatCulture, '{0} ms', $milliseconds)
    }

    if ($Duration.TotalMinutes -lt 1) {
        $seconds = [math]::Round($Duration.TotalSeconds, 2)
        return [string]::Format($script:durationFormatCulture, '{0:N2} seconds', $seconds)
    }

    $minutes = [int][math]::Floor($Duration.TotalMinutes)
    $secondsComponent = $Duration.Seconds
    return [string]::Format($script:durationFormatCulture, '{0}m {1:D2}s', $minutes, $secondsComponent)
}

$ansiSupported = Test-AnsiOutputSupport
if (-not $ansiSupported) {
    Disable-AnsiOutput
}

function Get-CollectorScripts {
    param([string]$Root)
    Get-ChildItem -Path $Root -Filter 'Collect-*.ps1' -Recurse |
        Where-Object { $_.FullName -ne $PSCommandPath -and $_.Name -notin @('Collect-All.ps1') } |
        Sort-Object DirectoryName, Name
}

function Invoke-AllCollectors {
    $resolvedOutputRoot = Resolve-CollectorOutputDirectory -RequestedPath $OutputRoot
    $collectors = Get-CollectorScripts -Root $PSScriptRoot

    if (-not $collectors) {
        Write-Warning 'No collector scripts were discovered. Nothing to run.'
        return
    }

    $expectedCollectors = @('Collect-Dhcp.ps1', 'Collect-Lan8021x.ps1', 'Collect-Lldp.ps1')
    foreach ($expected in $expectedCollectors) {
        if (-not ($collectors | Where-Object { $_.Name -ieq $expected })) {
            Write-Warning ("Expected collector '{0}' was not discovered; wired 802.1X data will be missing." -f $expected)
        }
    }

    if ($ThrottleLimit -lt 1) {
        $ThrottleLimit = [math]::Max([System.Environment]::ProcessorCount, 1)
    }

    $totalCollectors = $collectors.Count
    Write-Verbose ("Output root resolved to '{0}'" -f $resolvedOutputRoot)
    Write-Verbose ("Discovered {0} collector script(s)." -f $totalCollectors)
    Write-Verbose ("Executing collectors with a throttle limit of {0}." -f $ThrottleLimit)

    $collectorInfos = foreach ($collector in $collectors) {
        $areaName = Split-Path -Path $collector.DirectoryName -Leaf
        if ($areaName -eq 'Collectors') {
            $areaName = 'Misc'
        }

        $areaOutput = Join-Path -Path $resolvedOutputRoot -ChildPath $areaName

        [pscustomobject]@{
            Collector  = $collector
            AreaName   = $areaName
            AreaOutput = $areaOutput
        }
    }

    foreach ($group in $collectorInfos | Group-Object AreaName) {
        $areaPath = $group.Group[0].AreaOutput
        if (-not (Test-Path -LiteralPath $areaPath)) {
            $null = New-Item -ItemType Directory -Path $areaPath -Force
        }
    }

    $parallelism = [math]::Max($ThrottleLimit, 1)
    $activity = 'Running collector scripts'

    $durationFormatCultureValue = $script:durationFormatCulture
    $formatCollectorDurationFunction = ${function:Format-CollectorDuration}
    $forwardVerbose = $PSBoundParameters.ContainsKey('Verbose') -and [bool]$PSBoundParameters['Verbose']

    $resultsList = [System.Collections.Generic.List[object]]::new()
    $completed = 0
    $total = $collectorInfos.Count

    Invoke-Parallel -InputObject $collectorInfos -DegreeOfParallelism $parallelism -ProgressActivity $activity -ScriptBlock {
        param($info, $index, $cancellationToken)

        if (-not $script:durationFormatCulture) {
            $script:durationFormatCulture = $using:durationFormatCultureValue
        }

        $collectorPath = $info.Collector.FullName
        Write-Verbose ("Starting collector '{0}' for area '{1}' with output '{2}'." -f $collectorPath, $info.AreaName, $info.AreaOutput)

        $arguments = @{ OutputDirectory = $info.AreaOutput }
        if ($using:forwardVerbose) {
            $arguments['Verbose'] = $true
        }

        $start = Get-Date
        $errorRecord = $null
        $errorMessage = $null
        $output = $null
        $success = $false

        try {
            $output = & $collectorPath @arguments
            $success = $true
        } catch {
            $errorRecord = $_
            if ($_.Exception -and $_.Exception.Message) {
                $errorMessage = $_.Exception.Message
            } else {
                $errorMessage = $_ | Out-String
            }
        }

        $end = Get-Date
        $duration = $end - $start
        $durationText = & $using:formatCollectorDurationFunction -Duration $duration

        [pscustomobject]@{
            Script          = $collectorPath
            Area            = $info.AreaName
            Output          = $output
            Success         = $success
            Error           = $errorMessage
            ErrorRecord     = $errorRecord
            Duration        = $durationText
            DurationSeconds = [math]::Round($duration.TotalSeconds, 3)
        }
    } | ForEach-Object {
        $parallelResult = $_
        if (-not $parallelResult) {
            return
        }

        $collectorData = $parallelResult.Result
        if (-not $collectorData) {
            $itemInfo = $parallelResult.Item
            $collectorPath = if ($itemInfo -and $itemInfo.Collector) { $itemInfo.Collector.FullName } else { $null }
            $errorMessage = if ($parallelResult.ErrorRecord) { $parallelResult.ErrorRecord.Exception.Message } else { 'Unknown error' }
            $durationText = if ($parallelResult.DurationMs) {
                & ${function:Format-CollectorDuration} -Duration ([TimeSpan]::FromMilliseconds($parallelResult.DurationMs))
            } else {
                'N/A'
            }

            $collectorData = [pscustomobject]@{
                Script          = $collectorPath
                Area            = if ($itemInfo) { $itemInfo.AreaName } else { $null }
                Output          = $null
                Success         = $false
                Error           = $errorMessage
                ErrorRecord     = $parallelResult.ErrorRecord
                Duration        = $durationText
                DurationSeconds = if ($parallelResult.DurationMs) { [math]::Round($parallelResult.DurationMs / 1000, 3) } else { $null }
            }
        }

        $resultsList.Add($collectorData) | Out-Null
        $completed++
        $statusMessage = '{0} of {1} collectors completed' -f $completed, $total
        $collectorName = if ($collectorData.Script) { Split-Path -Path $collectorData.Script -Leaf } else { 'Unknown collector' }

        if ($collectorData.Success) {
            Write-Verbose ("Collector '{0}' finished successfully." -f $collectorData.Script)
        } else {
            Write-Verbose ("Collector '{0}' reported an exception." -f $collectorData.Script)
            Write-Warning ("Collector failed: {0} - {1}" -f $collectorData.Script, $collectorData.Error)
        }

        Write-Host ("Collector '{0}' completed in {1}. {2}" -f $collectorName, $collectorData.Duration, $statusMessage)
    }

    Write-Progress -Activity $activity -Completed

    $results = $resultsList.ToArray()

    $summary = [ordered]@{
        CollectedAt = (Get-Date).ToString('o')
        OutputRoot  = $resolvedOutputRoot
        Results     = $results
    }

    $summaryPath = Export-CollectorResult -OutputDirectory $resolvedOutputRoot -FileName 'collection-summary.json' -Data $summary -Depth 6
    Write-Verbose ("Summary exported to '{0}'." -f $summaryPath)
    Write-Host "Collection complete. Summary written to $summaryPath"
    Write-Output $summaryPath
}

Invoke-AllCollectors
