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

    $expectedCollectors = @('Collect-Lan8021x.ps1')
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
    Write-Verbose "Executing collectors sequentially."

    $resultsList = [System.Collections.Generic.List[object]]::new()
    $completed = 0
    $activity = 'Running collector scripts'

    foreach ($collector in $collectors) {
        $areaName = Split-Path -Path $collector.DirectoryName -Leaf
        if ($areaName -eq 'Collectors') {
            $areaName = 'Misc'
        }

        $areaOutput = Join-Path -Path $resolvedOutputRoot -ChildPath $areaName
        $null = Resolve-CollectorOutputDirectory -RequestedPath $areaOutput

        Write-Verbose ("Starting collector '{0}' for area '{1}' with output '{2}'." -f $collector.FullName, $areaName, $areaOutput)

        try {
            $result = & $collector.FullName -OutputDirectory $areaOutput -ErrorAction Stop
            Write-Verbose ("Collector '{0}' finished successfully." -f $collector.FullName)
            $resultsList.Add([pscustomobject]@{
                Script  = $collector.FullName
                Output  = $result
                Success = $true
                Error   = $null
            })
        } catch {
            Write-Verbose ("Collector '{0}' reported an exception." -f $collector.FullName)
            Write-Warning ("Collector failed: {0} - {1}" -f $collector.FullName, $_.Exception.Message)
            $resultsList.Add([pscustomobject]@{
                Script  = $collector.FullName
                Output  = $null
                Success = $false
                Error   = $_.Exception.Message
            })
        }

        $completed++
        $statusMessage = "[{0}/{1}] {2}" -f $completed, $totalCollectors, $collector.FullName
        $percentComplete = if ($totalCollectors -eq 0) { 100 } else { [int](($completed / $totalCollectors) * 100) }
        Write-Progress -Activity $activity -Status $statusMessage -PercentComplete $percentComplete
        Write-Host $statusMessage
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
