<#!
.SYNOPSIS
    Evaluates Office macro and Protected View policy artifacts and records findings.
#>

function Invoke-OfficePoliciesHeuristic {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

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
                        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Office macros allowed, so disabled MOTW or permissive macro settings expose the organization to macro malware.' -Evidence ("VBAWarnings={0} at {1}" -f $value, $policy.Path) -Subcategory 'Macro Policies'
                    }
                }

                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableTrustBarNotificationsFromUnsignedMacros']) {
                    $setting = [int]$policy.Values.DisableTrustBarNotificationsFromUnsignedMacros
                    if ($setting -eq 1) {
                        Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Trust Bar notifications disabled, so disabled MOTW or permissive macro settings expose the organization to macro malware.' -Evidence $policy.Path -Subcategory 'Macro Policies'
                    }
                }

                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableProtectedViewForAttachments']) {
                    if ([int]$policy.Values.DisableProtectedViewForAttachments -eq 1) {
                        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Protected View disabled for attachments, so disabled Protected View lets untrusted files open directly.' -Evidence $policy.Path -Subcategory 'Protected View Policies'
                    }
                }
            }

            if ($macroBlocked) {
                Add-CategoryNormal -CategoryResult $Result -Title 'Macro runtime blocked by policy' -Subcategory 'Macro Policies'
            }
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Office MOTW macro blocking - no data, so disabled MOTW or permissive macro settings could expose the organization to macro malware.' -Subcategory 'Macro Policies'
            Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Office macro notifications - no data, so macro security gaps could expose the organization to macro malware.' -Subcategory 'Macro Policies'
            Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Office Protected View - no data, so disabled Protected View could let untrusted files open directly.' -Subcategory 'Protected View Policies'
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Office MOTW macro blocking - no data, so disabled MOTW or permissive macro settings could expose the organization to macro malware.' -Subcategory 'Macro Policies'
        Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Office macro notifications - no data, so macro security gaps could expose the organization to macro malware.' -Subcategory 'Macro Policies'
        Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Office Protected View - no data, so disabled Protected View could let untrusted files open directly.' -Subcategory 'Protected View Policies'
    }
}
