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

    # Structured remediation mapping for macro blocking:
    # - Deployment instruction -> text step.
    # - Registry value list -> text + code steps using the reg language hint.
    # - Trust Bar reminder -> note step.
    $macroPolicyRemediation = @'
[
  {
    "type": "text",
    "content": "Deploy the Intune or Group Policy setting \"Block macros from running in Office files from the Internet\" for Word, Excel, and PowerPoint so MOTW content cannot run."
  },
  {
    "type": "text",
    "title": "Registry values",
    "content": "Set these keys to enforce macro blocking."
  },
  {
    "type": "code",
    "lang": "reg",
    "content": "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\blockcontentexecutionfrominternet=1\nHKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\blockcontentexecutionfrominternet=1\nHKCU\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\\blockcontentexecutionfrominternet=1"
  },
  {
    "type": "note",
    "content": "Leave DisableTrustBarNotificationsFromUnsignedMacros at 0 so Office shows the Trust Bar, then open a Mark-of-the-Web document to confirm it is blocked or only opens in Protected View."
  }
]
'@

    # Structured remediation mapping for missing macro policy data:
    # - Collection reminder and policy deployment remain sequential text steps.
    # - Registry snippet stays a code step.
    # - Validation note references the Mark-of-the-Web test.
    $macroPolicyDataRemediation = @'
[
  {
    "type": "text",
    "content": "Re-run the Office policy collector or inspect the device manually to confirm macro blocking is enforced."
  },
  {
    "type": "text",
    "content": "Apply the \"Block macros from running in Office files from the Internet\" policy for Word, Excel, and PowerPoint so MOTW content cannot run."
  },
  {
    "type": "code",
    "lang": "reg",
    "content": "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\blockcontentexecutionfrominternet=1\nHKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\blockcontentexecutionfrominternet=1\nHKCU\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\\blockcontentexecutionfrominternet=1"
  },
  {
    "type": "note",
    "content": "Leave DisableTrustBarNotificationsFromUnsignedMacros at 0 and validate with a Mark-of-the-Web document to ensure it is blocked or only opens in Protected View."
  }
]
'@

    # Structured remediation mapping for Trust Bar policy:
    # - Trust Bar re-enable instruction -> text step.
    # - Macro policy deployment -> text step plus registry code block.
    # - Final validation remains a note.
    $trustBarRemediation = @'
[
  {
    "type": "text",
    "content": "Re-enable Trust Bar notifications by leaving DisableTrustBarNotificationsFromUnsignedMacros unset or 0 in user policy."
  },
  {
    "type": "text",
    "content": "Deploy the \"Block macros from running in Office files from the Internet\" policy for Word, Excel, and PowerPoint so MOTW content cannot run."
  },
  {
    "type": "code",
    "lang": "reg",
    "content": "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\blockcontentexecutionfrominternet=1\nHKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\blockcontentexecutionfrominternet=1\nHKCU\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\\blockcontentexecutionfrominternet=1"
  },
  {
    "type": "note",
    "content": "Open a Mark-of-the-Web document to confirm Office shows the Trust Bar and blocks or sandboxes the file."
  }
]
'@

    # Structured remediation mapping for missing Trust Bar data:
    # - Collection reminder and policy guidance -> text steps.
    # - Registry list stays a code step.
    # - Validation remains a note about MOTW testing.
    $trustBarDataRemediation = @'
[
  {
    "type": "text",
    "content": "Re-run the Office policy collector or review the device's policy results to confirm Trust Bar prompts are enabled."
  },
  {
    "type": "text",
    "content": "Keep DisableTrustBarNotificationsFromUnsignedMacros unset or 0 and deploy macro blocking for Word, Excel, and PowerPoint so MOTW content cannot run."
  },
  {
    "type": "code",
    "lang": "reg",
    "content": "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\blockcontentexecutionfrominternet=1\nHKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\blockcontentexecutionfrominternet=1\nHKCU\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\\blockcontentexecutionfrominternet=1"
  },
  {
    "type": "note",
    "content": "Open a Mark-of-the-Web document to confirm Office shows the Trust Bar and blocks or sandboxes the file."
  }
]
'@

    # Structured remediation mapping for Protected View enforcement:
    # - Policy instruction -> text step.
    # - Registry change -> text + code steps.
    # - Validation remains a note about MOTW attachments.
    $protectedViewRemediation = @'
[
  {
    "type": "text",
    "content": "Re-enable Protected View for attachments through Intune or Group Policy so MOTW content opens in the sandbox."
  },
  {
    "type": "text",
    "title": "Registry value",
    "content": "Set this key to 0 to keep Protected View enabled for attachments."
  },
  {
    "type": "code",
    "lang": "reg",
    "content": "HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\Trust Center\\DisableAttachmentsInPV=0"
  },
  {
    "type": "note",
    "content": "Open a Mark-of-the-Web attachment to confirm it opens in Protected View instead of editing mode."
  }
]
'@

    # Structured remediation mapping for missing Protected View data:
    # - Collection reminder and registry configuration -> text and code steps.
    # - Validation note mirrors the legacy paragraph.
    $protectedViewDataRemediation = @'
[
  {
    "type": "text",
    "content": "Re-run the Office policy collector or inspect the device manually to confirm Protected View is enforced for attachments."
  },
  {
    "type": "text",
    "content": "Set the following registry value through Intune or Group Policy."
  },
  {
    "type": "code",
    "lang": "reg",
    "content": "HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\Trust Center\\DisableAttachmentsInPV=0"
  },
  {
    "type": "note",
    "content": "Open a Mark-of-the-Web attachment to verify it opens in Protected View instead of editing mode."
  }
]
'@

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
                        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Office macros allowed, so disabled MOTW or permissive macro settings expose the organization to macro malware.' -Evidence ("VBAWarnings={0} at {1}" -f $value, $policy.Path) -Remediation $macroPolicyRemediation -Subcategory 'Macro Policies'
                    }
                }

                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableTrustBarNotificationsFromUnsignedMacros']) {
                    $setting = [int]$policy.Values.DisableTrustBarNotificationsFromUnsignedMacros
                    if ($setting -eq 1) {
                        Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Trust Bar notifications disabled, so disabled MOTW or permissive macro settings expose the organization to macro malware.' -Evidence $policy.Path -Remediation $trustBarRemediation -Subcategory 'Macro Policies'
                    }
                }

                if ($policy.Values -and $policy.Values.PSObject.Properties['DisableProtectedViewForAttachments']) {
                    if ([int]$policy.Values.DisableProtectedViewForAttachments -eq 1) {
                        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Protected View disabled for attachments, so disabled Protected View lets untrusted files open directly.' -Evidence $policy.Path -Remediation $protectedViewRemediation -Subcategory 'Protected View Policies'
                    }
                }
            }

            if ($macroBlocked) {
                Add-CategoryNormal -CategoryResult $Result -Title 'Macro runtime blocked by policy' -Subcategory 'Macro Policies'
            }
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Office MOTW macro blocking - no data, so disabled MOTW or permissive macro settings could expose the organization to macro malware.' -Remediation $macroPolicyDataRemediation -Subcategory 'Macro Policies'
            Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Office macro notifications - no data, so macro security gaps could expose the organization to macro malware.' -Remediation $trustBarDataRemediation -Subcategory 'Macro Policies'
            Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Office Protected View - no data, so disabled Protected View could let untrusted files open directly.' -Remediation $protectedViewDataRemediation -Subcategory 'Protected View Policies'
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Office MOTW macro blocking - no data, so disabled MOTW or permissive macro settings could expose the organization to macro malware.' -Remediation $macroPolicyDataRemediation -Subcategory 'Macro Policies'
        Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Office macro notifications - no data, so macro security gaps could expose the organization to macro malware.' -Remediation $trustBarDataRemediation -Subcategory 'Macro Policies'
        Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Office Protected View - no data, so disabled Protected View could let untrusted files open directly.' -Remediation $protectedViewDataRemediation -Subcategory 'Protected View Policies'
    }
}
