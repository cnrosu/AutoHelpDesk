<#!
.SYNOPSIS
    Office security heuristics covering macro and Protected View policies along with cache sizing.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')
$officeHeuristicRoot = Join-Path $PSScriptRoot 'Office'
. (Join-Path $officeHeuristicRoot 'OfficePolicies.ps1')
. (Join-Path $officeHeuristicRoot 'OutlookCache.ps1')
. (Join-Path $officeHeuristicRoot 'OutlookConnectivity.ps1')
. (Join-Path $officeHeuristicRoot 'AutodiscoverDns.ps1')

function Invoke-OfficeHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Office' -Message 'Starting Office heuristics' -Data ([ordered]@{
        ArtifactCount = $( if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 } )
    })

    $result = New-CategoryResult -Name 'Office'

    Invoke-OfficePoliciesHeuristic      -Context $Context -Result $result
    Invoke-OutlookCacheHeuristic        -Context $Context -Result $result
    Invoke-OutlookConnectivityHeuristic -Context $Context -Result $result
    Invoke-AutodiscoverDnsHeuristic     -Context $Context -Result $result

    return $result
}
