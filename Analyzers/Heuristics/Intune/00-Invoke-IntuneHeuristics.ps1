<#!
.SYNOPSIS
    Entry point that evaluates all Intune heuristics and returns the combined category result.
#>

function Invoke-IntuneHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Intune' -Message 'Starting Intune heuristics evaluation' -Data ([ordered]@{
        HasArtifacts = [bool]($Context -and $Context.Artifacts)
    })

    $result = New-CategoryResult -Name 'Intune'
    Invoke-IntuneHeuristic-INTUNE-001 -Context $Context -Result $result
    Invoke-IntuneHeuristic-INTUNE-002 -Context $Context -Result $result
    Invoke-IntuneHeuristic-INTUNE-003 -Context $Context -Result $result
    return $result
}
