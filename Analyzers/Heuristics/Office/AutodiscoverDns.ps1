<#!
.SYNOPSIS
    Evaluates Autodiscover DNS artifacts for Exchange Online readiness.
#>

function Invoke-AutodiscoverDnsHeuristic {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    $autodiscoverArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autodiscover-dns'
    Write-HeuristicDebug -Source 'Office' -Message 'Resolved autodiscover-dns artifact' -Data ([ordered]@{
        Found = [bool]$autodiscoverArtifact
    })

    if (-not $autodiscoverArtifact) {
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autodiscoverArtifact)
    Write-HeuristicDebug -Source 'Office' -Message 'Evaluating autodiscover DNS payload' -Data ([ordered]@{
        HasResults = [bool]($payload -and $payload.Results)
    })

    if (-not ($payload -and $payload.Results)) {
        return
    }

    $results = if ($payload.Results -is [System.Collections.IEnumerable] -and -not ($payload.Results -is [string])) { @($payload.Results) } else { @($payload.Results) }
    foreach ($domainEntry in $results) {
        if (-not $domainEntry) { continue }

        $domain = $domainEntry.Domain
        $autoRecord = ($domainEntry.Lookups | Where-Object { $_.Label -eq 'Autodiscover' } | Select-Object -First 1)
        if (-not $autoRecord) { continue }

        $targetsRaw = if ($autoRecord.Targets -is [System.Collections.IEnumerable] -and -not ($autoRecord.Targets -is [string])) { @($autoRecord.Targets) } else { @($autoRecord.Targets) }
        $targetsClean = $targetsRaw | Where-Object { $_ }

        if ($autoRecord.Success -eq $true -and $targetsClean.Count -gt 0) {
            $targets = $targetsClean
            $targetText = $targets -join ', '
            if ($targets -match 'autodiscover\\.outlook\\.com') {
                Add-CategoryNormal -CategoryResult $Result -Title ("Autodiscover CNAME healthy for {0}" -f $domain) -Evidence $targetText -Subcategory 'Autodiscover DNS'
            } else {
                Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title ("Autodiscover for {0} points to {1}, so missing or invalid Autodiscover records cause mail setup failures." -f $domain, $targetText) -Evidence 'Expected autodiscover.outlook.com for Exchange Online onboarding.' -Subcategory 'Autodiscover DNS'
            }
        } elseif ($autoRecord.Success -eq $false) {
            $evidence = if ($autoRecord.Error) { $autoRecord.Error } else { "Lookup failed for autodiscover.$domain" }
            Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title ("Cannot locate Exchange Services for {0}, so missing or invalid Autodiscover records cause mail setup failures." -f $domain) -Evidence $evidence -Subcategory 'Autodiscover DNS'
        }
    }
}
