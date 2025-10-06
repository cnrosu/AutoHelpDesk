<#!
.SYNOPSIS
    Evaluates Outlook connectivity OST file artifact.
#>

function Invoke-OutlookConnectivityHeuristic {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    $connectivityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-connectivity'
    Write-HeuristicDebug -Source 'Office' -Message 'Resolved outlook-connectivity artifact' -Data ([ordered]@{
        Found = [bool]$connectivityArtifact
    })

    if ($connectivityArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $connectivityArtifact)
        Write-HeuristicDebug -Source 'Office' -Message 'Evaluating Outlook connectivity payload' -Data ([ordered]@{
            OstCount = $( if ($payload -and $payload.OstFiles) { $payload.OstFiles.Count } else { 0 } )
        })

        if ($payload -and $payload.OstFiles) {
            $largeOst = $payload.OstFiles | Where-Object { $_.Length -gt 25GB }
            if ($largeOst.Count -gt 0) {
                $names = $largeOst.Name
                Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title ('Large OST files detected: {0}, so oversized OST caches can slow Outlook performance.' -f ($names -join ', ')) -Subcategory 'Outlook Data Files'
            } elseif ($payload.OstFiles.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $Result -Title ('OST files present ({0})' -f $payload.OstFiles.Count) -Subcategory 'Outlook Data Files'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Outlook data file inventory not collected, so oversized OST files may be missed.' -Subcategory 'Outlook Data Files'
    }
}
