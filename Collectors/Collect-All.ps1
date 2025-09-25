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
    [string]$OutputRoot = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath 'output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'CollectorCommon.ps1')

function Get-CollectorScripts {
    param([string]$Root)
    Get-ChildItem -Path $Root -Filter 'Collect-*.ps1' -Recurse |
        Where-Object { $_.FullName -ne $PSCommandPath -and $_.Name -notin @('Collect-All.ps1') } |
        Sort-Object DirectoryName, Name
}

function Invoke-CollectorScript {
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$Script,

        [Parameter(Mandatory)]
        [string]$OutputDirectory
    )

    Write-Verbose "Running collector: $($Script.FullName)"
    try {
        $result = & $Script.FullName -OutputDirectory $OutputDirectory -ErrorAction Stop
        return [PSCustomObject]@{
            Script      = $Script.FullName
            Output      = $result
            Success     = $true
            Error       = $null
        }
    } catch {
        Write-Warning "Collector failed: $($Script.FullName) - $($_.Exception.Message)"
        return [PSCustomObject]@{
            Script  = $Script.FullName
            Output  = $null
            Success = $false
            Error   = $_.Exception.Message
        }
    }
}

function Invoke-AllCollectors {
    $resolvedOutputRoot = Resolve-CollectorOutputDirectory -RequestedPath $OutputRoot
    $collectors = Get-CollectorScripts -Root $PSScriptRoot

    if (-not $collectors) {
        Write-Warning 'No collector scripts were discovered. Nothing to run.'
        return
    }

    $results = @()
    $totalCollectors = $collectors.Count
    $currentIndex = 0

    foreach ($collector in $collectors) {
        $currentIndex++
        $statusMessage = "[{0}/{1}] {2}" -f $currentIndex, $totalCollectors, $collector.FullName
        $percentComplete = [int]((($currentIndex - 1) / $totalCollectors) * 100)

        Write-Progress -Activity 'Running collector scripts' -Status $statusMessage -PercentComplete $percentComplete
        Write-Host $statusMessage

        $areaName = Split-Path -Path $collector.DirectoryName -Leaf
        if ($areaName -eq 'Collectors') {
            $areaName = 'Misc'
        }
        $areaOutput = Join-Path -Path $resolvedOutputRoot -ChildPath $areaName
        $null = Resolve-CollectorOutputDirectory -RequestedPath $areaOutput
        $results += Invoke-CollectorScript -Script $collector -OutputDirectory $areaOutput
    }

    Write-Progress -Activity 'Running collector scripts' -Completed

    $summary = [ordered]@{
        CollectedAt = (Get-Date).ToString('o')
        OutputRoot  = $resolvedOutputRoot
        Results     = $results
    }

    $summaryPath = Export-CollectorResult -OutputDirectory $resolvedOutputRoot -FileName 'collection-summary.json' -Data $summary -Depth 6
    Write-Host "Collection complete. Summary written to $summaryPath"
    Write-Output $summaryPath
}

Invoke-AllCollectors
