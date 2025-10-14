<#!
.SYNOPSIS
    Cloud service heuristics covering OneDrive configuration and health.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')
$cloudHeuristicRoot = Join-Path $PSScriptRoot 'Cloud'
. (Join-Path $cloudHeuristicRoot 'OneDrive.ps1')

function Invoke-CloudHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Cloud' -Message 'Starting cloud heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Cloud'

    Invoke-OneDriveHeuristic -Context $Context -Result $result

    return $result
}
