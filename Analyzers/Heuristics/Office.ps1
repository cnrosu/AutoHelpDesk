<#!
.SYNOPSIS
    Office security heuristics covering macro and Protected View policies along with cache sizing.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Invoke-OfficeHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Office' -Message 'Starting Office heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Office'

    $policiesArtifact = Get-AnalyzerArtifact -Context $Context -Name 'office-policies'
    Write-HeuristicDebug -Source 'Office' -Message 'Resolved office-policies artifact' -Data ([ordered]@{
        Found = [bool]$policiesArtifact
    })
    if ($policiesArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $policiesArtifact)
        Write-HeuristicDebug -Source 'Office' -Message 'Evaluating Office policies payload' -Data ([ordered]@{
            HasPolicies = [bool]($payload -and $payload.Policies)
        })
        if ($payload -and $payload.Policies) {
            $macroBlocked = $false
            foreach ($policy in $payload.Policies) {
                Write-HeuristicDebug -Source 'Office' -Message 'Processing policy entry' -Data ([ordered]@{
                    Path = $policy.Path
                })
                if ($policy.Values -and $policy.Values.PSObject.Properties['VBAWarnings']) {
                    $value = [int]$policy.Values.VBAWarnings
                    if ($value -ge 4) {
                        $macroBlocked = $true
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Office macros allowed, so disabled MOTW or permissive macro settings expose the organization to macro malware.' -Evidence ("VBAWarnings={0} at {1}" -f $value, $policy.Path) -Subcategory 'Macro Policies'
                    }
                }
                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableTrustBarNotificationsFromUnsignedMacros']) {
                    $setting = [int]$policy.Values.DisableTrustBarNotificationsFromUnsignedMacros
                    if ($setting -eq 1) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Trust Bar notifications disabled, so disabled MOTW or permissive macro settings expose the organization to macro malware.' -Evidence $policy.Path -Subcategory 'Macro Policies'
                    }
                }
                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableProtectedViewForAttachments']) {
                    if ([int]$policy.Values.DisableProtectedViewForAttachments -eq 1) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Protected View disabled for attachments, so disabled Protected View lets untrusted files open directly.' -Evidence $policy.Path -Subcategory 'Protected View Policies'
                    }
                }
            }

            if ($macroBlocked) {
                Add-CategoryNormal -CategoryResult $result -Title 'Macro runtime blocked by policy' -Subcategory 'Macro Policies'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Office MOTW macro blocking - no data, so disabled MOTW or permissive macro settings could expose the organization to macro malware.' -Subcategory 'Macro Policies'
            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Office macro notifications - no data, so macro security gaps could expose the organization to macro malware.' -Subcategory 'Macro Policies'
            Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Office Protected View - no data, so disabled Protected View could let untrusted files open directly.' -Subcategory 'Protected View Policies'
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Office MOTW macro blocking - no data, so disabled MOTW or permissive macro settings could expose the organization to macro malware.' -Subcategory 'Macro Policies'
        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Office macro notifications - no data, so macro security gaps could expose the organization to macro malware.' -Subcategory 'Macro Policies'
        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Office Protected View - no data, so disabled Protected View could let untrusted files open directly.' -Subcategory 'Protected View Policies'
    }

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
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Large Outlook cache files detected, so oversized OST caches can slow Outlook performance.' -Evidence ($names -join "`n") -Subcategory 'Outlook Cache'
            } elseif ($payload.Caches.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Outlook cache files present ({0})' -f $payload.Caches.Count) -Subcategory 'Outlook Cache'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Outlook cache inventory not collected, so oversized cache files may be missed.' -Subcategory 'Outlook Cache'
    }

    $connectivityArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-connectivity'
    Write-HeuristicDebug -Source 'Office' -Message 'Resolved outlook-connectivity artifact' -Data ([ordered]@{
        Found = [bool]$connectivityArtifact
    })
    if ($connectivityArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $connectivityArtifact)
        Write-HeuristicDebug -Source 'Office' -Message 'Evaluating Outlook connectivity payload' -Data ([ordered]@{
            OstCount = if ($payload -and $payload.OstFiles) { $payload.OstFiles.Count } else { 0 }
        })
        if ($payload -and $payload.OstFiles) {
            $largeOst = $payload.OstFiles | Where-Object { $_.Length -gt 25GB }
            if ($largeOst.Count -gt 0) {
                $names = $largeOst.Name
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ('Large OST files detected: {0}, so oversized OST caches can slow Outlook performance.' -f ($names -join ', ')) -Subcategory 'Outlook Data Files'
            } elseif ($payload.OstFiles.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('OST files present ({0})' -f $payload.OstFiles.Count) -Subcategory 'Outlook Data Files'
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Outlook data file inventory not collected, so oversized OST files may be missed.' -Subcategory 'Outlook Data Files'
    }

    $autodiscoverArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autodiscover-dns'
    Write-HeuristicDebug -Source 'Office' -Message 'Resolved autodiscover-dns artifact' -Data ([ordered]@{
        Found = [bool]$autodiscoverArtifact
    })
    if ($autodiscoverArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autodiscoverArtifact)
        Write-HeuristicDebug -Source 'Office' -Message 'Evaluating autodiscover DNS payload' -Data ([ordered]@{
            HasResults = [bool]($payload -and $payload.Results)
        })
        if ($payload -and $payload.Results) {
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
                    if ($targets -match 'autodiscover\.outlook\.com') {
                        Add-CategoryNormal -CategoryResult $result -Title ("Autodiscover CNAME healthy for {0}" -f $domain) -Evidence $targetText -Subcategory 'Autodiscover DNS'
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title ("Autodiscover for {0} points to {1}, so missing or invalid Autodiscover records cause mail setup failures." -f $domain, $targetText) -Evidence 'Expected autodiscover.outlook.com for Exchange Online onboarding.' -Subcategory 'Autodiscover DNS'
                    }
                } elseif ($autoRecord.Success -eq $false) {
                    $evidence = if ($autoRecord.Error) { $autoRecord.Error } else { "Lookup failed for autodiscover.$domain" }
                    Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title ("Cannot locate Exchange Services for {0}, so missing or invalid Autodiscover records cause mail setup failures." -f $domain) -Evidence $evidence -Subcategory 'Autodiscover DNS'
                }
            }
        }
    }

    return $result
}
