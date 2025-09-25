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

    $result = New-CategoryResult -Name 'Office'

    $policiesArtifact = Get-AnalyzerArtifact -Context $Context -Name 'office-policies'
    if ($policiesArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $policiesArtifact)
        if ($payload -and $payload.Policies) {
            $macroBlocked = $false
            foreach ($policy in $payload.Policies) {
                if ($policy.Values -and $policy.Values.PSObject.Properties['VBAWarnings']) {
                    $value = [int]$policy.Values.VBAWarnings
                    if ($value -ge 4) {
                        $macroBlocked = $true
                    } else {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Office macros allowed' -Evidence ("VBAWarnings={0} at {1}" -f $value, $policy.Path)
                    }
                }
                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableTrustBarNotificationsFromUnsignedMacros']) {
                    $setting = [int]$policy.Values.DisableTrustBarNotificationsFromUnsignedMacros
                    if ($setting -eq 1) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'low' -Title 'Trust Bar notifications disabled' -Evidence $policy.Path
                    }
                }
                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableProtectedViewForAttachments']) {
                    if ([int]$policy.Values.DisableProtectedViewForAttachments -eq 1) {
                        Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Protected View disabled for attachments' -Evidence $policy.Path
                    }
                }
            }

            if ($macroBlocked) {
                Add-CategoryNormal -CategoryResult $result -Title 'Macro runtime blocked by policy'
            }
        } else {
            Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'No Office policy data collected'
        }
    }

    $cacheArtifact = Get-AnalyzerArtifact -Context $Context -Name 'outlook-caches'
    if ($cacheArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $cacheArtifact)
        if ($payload -and $payload.Caches -and -not $payload.Caches.Error) {
            $largeCaches = $payload.Caches | Where-Object { $_.Length -gt 25GB }
            if ($largeCaches.Count -gt 0) {
                $names = $largeCaches | Select-Object -ExpandProperty FullName -First 5
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title 'Large Outlook cache files detected' -Evidence ($names -join "`n")
            } elseif ($payload.Caches.Count -gt 0) {
                Add-CategoryNormal -CategoryResult $result -Title ('Outlook cache files present ({0})' -f $payload.Caches.Count)
            }
        }
    }

    return $result
}
