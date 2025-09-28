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

    if ($ThrottleLimit -lt 1) {
        $ThrottleLimit = [math]::Max([System.Environment]::ProcessorCount, 1)
    }

    $totalCollectors = $collectors.Count
    $effectiveThrottle = [math]::Max([math]::Min($ThrottleLimit, $totalCollectors), 1)

    Write-Verbose ("Output root resolved to '{0}'" -f $resolvedOutputRoot)
    Write-Verbose ("Discovered {0} collector script(s)." -f $totalCollectors)
    Write-Verbose ("Using throttle limit {0}." -f $effectiveThrottle)

    $collectorScript = @'
param($scriptPath, $outputDirectory, $parentVerbosePreference)
$VerbosePreference = $parentVerbosePreference
$ErrorActionPreference = "Stop"
try {
    Write-Verbose ("Starting collector '{0}' with output '{1}'." -f $scriptPath, $outputDirectory)
    $result = & $scriptPath -OutputDirectory $outputDirectory -ErrorAction Stop
    Write-Verbose ("Collector '{0}' finished successfully." -f $scriptPath)
    [pscustomobject]@{
        Script  = $scriptPath
        Output  = $result
        Success = $true
        Error   = $null
    }
} catch {
    Write-Verbose ("Collector '{0}' reported an exception." -f $scriptPath)
    Write-Warning ("Collector failed: {0} - {1}" -f $scriptPath, $_.Exception.Message)
    [pscustomobject]@{
        Script  = $scriptPath
        Output  = $null
        Success = $false
        Error   = $_.Exception.Message
    }
}
'@

    $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $runspacePool = $null
    $results = @()

    try {
        $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $effectiveThrottle, $initialSessionState, $Host)
        $runspacePool.Open()

        $pending = [System.Collections.Generic.List[object]]::new()

        foreach ($collector in $collectors) {
            $areaName = Split-Path -Path $collector.DirectoryName -Leaf
            if ($areaName -eq 'Collectors') {
                $areaName = 'Misc'
            }

            $areaOutput = Join-Path -Path $resolvedOutputRoot -ChildPath $areaName
            $null = Resolve-CollectorOutputDirectory -RequestedPath $areaOutput

            Write-Verbose ("Queueing collector '{0}' for area '{1}' with output '{2}'." -f $collector.FullName, $areaName, $areaOutput)

            $psInstance = [System.Management.Automation.PowerShell]::Create()
            $psInstance.RunspacePool = $runspacePool
            $null = $psInstance.AddScript($collectorScript, $true).
                AddArgument($collector.FullName).
                AddArgument($areaOutput).
                AddArgument($VerbosePreference)

            $asyncResult = $psInstance.BeginInvoke()
            $pending.Add([pscustomobject]@{
                PowerShell  = $psInstance
                AsyncResult = $asyncResult
                Collector   = $collector
            })
        }

        $resultsList = [System.Collections.Generic.List[object]]::new()
        $completed = 0
        $activity = 'Running collector scripts'

        while ($pending.Count -gt 0) {
            for ($index = $pending.Count - 1; $index -ge 0; $index--) {
                $entry = $pending[$index]
                if (-not $entry.AsyncResult.IsCompleted) {
                    continue
                }

                try {
                    $output = $entry.PowerShell.EndInvoke($entry.AsyncResult)
                } finally {
                    $entry.PowerShell.Dispose()
                }

                foreach ($item in $output) {
                    $resultsList.Add($item)
                }

                $pending.RemoveAt($index)
                $completed++

                $statusMessage = "[{0}/{1}] {2}" -f $completed, $totalCollectors, $entry.Collector.FullName
                $percentComplete = if ($totalCollectors -eq 0) { 100 } else { [int](($completed / $totalCollectors) * 100) }
                Write-Progress -Activity $activity -Status $statusMessage -PercentComplete $percentComplete
                Write-Host $statusMessage
                $firstResult = if ($output) { $output | Select-Object -First 1 } else { $null }
                $successState = if ($firstResult) { $firstResult.Success } else { $null }
                Write-Verbose ("Collector '{0}' result recorded. Success: {1}." -f $entry.Collector.FullName, $successState)
            }

            if ($pending.Count -gt 0) {
                Start-Sleep -Milliseconds 100
            }
        }

        Write-Progress -Activity $activity -Completed

        $results = $resultsList.ToArray()

    } finally {
        if ($runspacePool) {
            $runspacePool.Close()
            $runspacePool.Dispose()
        }
    }

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
