<#!
.SYNOPSIS
    Evaluates Outlook cache inventory artifacts.
#>

function Invoke-OutlookCacheHeuristic {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    $cacheArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-caches'
    Write-HeuristicDebug -Source 'Office' -Message 'Resolved outlook-caches artifact' -Data ([ordered]@{
        Found = [bool]$cacheArtifact
    })

    if ($cacheArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $cacheArtifact)
        Write-HeuristicDebug -Source 'Office' -Message 'Evaluating Outlook caches payload' -Data ([ordered]@{
            CacheCount = if ($payload -and $payload.Caches) { $payload.Caches.Count } else { 0 }
        })

        if ($payload -and $payload.Caches -and -not $payload.Caches.Error) {
            $largeCaches = $payload.Caches | Where-Object { $_.Length -gt 25GB }
            if ($largeCaches.Count -gt 0) {
                $names = $largeCaches | Select-Object -ExpandProperty FullName -First 5
                Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Large Outlook cache files detected, so oversized OST caches can slow Outlook performance.' -Evidence ($names -join "`n") -Subcategory 'Outlook Cache'
            } elseif ($payload.Caches.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $Result -Title ('Outlook cache files present ({0})' -f $payload.Caches.Count) -Subcategory 'Outlook Cache'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Outlook cache inventory not collected, so oversized cache files may be missed.' -Subcategory 'Outlook Cache'
    }
}
