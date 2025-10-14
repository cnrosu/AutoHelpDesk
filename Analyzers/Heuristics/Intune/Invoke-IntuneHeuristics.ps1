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
    Invoke-IntuneHeuristic-EnrollmentConnectivityHealth -Context $Context -Result $result
    Invoke-IntuneHeuristic-Win32EspAppHealth -Context $Context -Result $result
    Invoke-IntuneHeuristic-PushNotificationQuickSync -Context $Context -Result $result
    return $result
}
