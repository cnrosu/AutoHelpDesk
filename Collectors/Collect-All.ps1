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

    $pool = [runspacefactory]::CreateRunspacePool(1, [math]::Max($ThrottleLimit, 1))
    $pool.ApartmentState = 'MTA'
    $pool.Open()

    $tasks = [System.Collections.Generic.List[object]]::new()
    foreach ($info in $collectorInfos) {
        Write-Verbose ("Starting collector '{0}' for area '{1}' with output '{2}'." -f $info.Collector.FullName, $info.AreaName, $info.AreaOutput)

        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool

        [void]$ps.AddCommand($info.Collector.FullName).AddParameter('OutputDirectory', $info.AreaOutput)

        if ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) {
            [void]$ps.AddParameter('Verbose')
        }

        $startTime = Get-Date
        $asyncResult = $ps.BeginInvoke()

        $task = [pscustomobject]@{
            PS       = $ps
            IAsync   = $asyncResult
            Path     = $info.Collector.FullName
            Area     = $info.AreaName
            Started  = $startTime
        }

        [void]$tasks.Add($task)
    }

    $resultsList = [System.Collections.Generic.List[object]]::new()
    $completed = 0
    $total = $tasks.Count
    $activity = 'Running collector scripts'

    $pendingTasks = [System.Collections.Generic.List[object]]::new()
    foreach ($task in $tasks) {
        [void]$pendingTasks.Add($task)
    }

    while ($pendingTasks.Count -gt 0) {
        $processedInThisCycle = $false

        foreach ($task in @($pendingTasks)) {
            if (-not $task.IAsync.IsCompleted) {
                continue
            }

            $completedAt = Get-Date
            $duration = $completedAt - $task.Started
            $formattedDuration = Format-CollectorDuration -Duration $duration

            try {
                $output = $task.PS.EndInvoke($task.IAsync)
                $resultsList.Add([pscustomobject]@{
                    Script  = $task.Path
                    Output  = $output
                    Success = $true
                    Error   = $null
                    Duration = $formattedDuration
                    DurationSeconds = [math]::Round($duration.TotalSeconds, 3)
                })
            } catch {
                Write-Verbose ("Collector '{0}' reported an exception." -f $task.Path)
                Write-Warning ("Collector failed: {0} - {1}" -f $task.Path, $_.Exception.Message)
                $resultsList.Add([pscustomobject]@{
                    Script  = $task.Path
                    Output  = $null
                    Success = $false
                    Error   = $_.Exception.Message
                    Duration = $formattedDuration
                    DurationSeconds = [math]::Round($duration.TotalSeconds, 3)
                })
            } finally {
                if ($task.IAsync.AsyncWaitHandle) {
                    $task.IAsync.AsyncWaitHandle.Dispose()
                }

                $task.PS.Dispose()
                $completed++
                $statusMessage = '{0} of {1} collectors completed' -f $completed, $total
                $percentComplete = if ($total -eq 0) { 100 } else { [int](($completed / [double]$total) * 100) }
                $currentOperation = 'Completed {0}' -f (Split-Path -Path $task.Path -Leaf)
                Write-Progress -Activity $activity -Status $statusMessage -PercentComplete $percentComplete -CurrentOperation $currentOperation
                $collectorName = Split-Path -Path $task.Path -Leaf
                Write-Host ("Collector '{0}' completed in {1}. {2}" -f $collectorName, $formattedDuration, $statusMessage)
                [void]$pendingTasks.Remove($task)
                $processedInThisCycle = $true
            }
        }

        if (-not $processedInThisCycle) {
            Start-Sleep -Milliseconds 100
        }
    }

    Write-Progress -Activity $activity -Completed
    $pool.Close()
    $pool.Dispose()

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
