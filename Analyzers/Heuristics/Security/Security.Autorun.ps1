function Invoke-SecurityAutorunChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $CategoryResult
    )

    $autorunArtifact = Get-AnalyzerArtifact -Context $Context -Name 'autorun'
    Write-HeuristicDebug -Source 'Security' -Message 'Resolved autorun artifact' -Data ([ordered]@{
        Found = [bool]$autorunArtifact
    })
    if ($autorunArtifact) {
        $autorunPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $autorunArtifact)
        Write-HeuristicDebug -Source 'Security' -Message 'Evaluating autorun payload' -Data ([ordered]@{
            HasPayload = [bool]$autorunPayload
        })

        if ($autorunPayload -and $autorunPayload.ExplorerPolicies) {
            $autorunEntries = ConvertTo-List $autorunPayload.ExplorerPolicies
            Write-HeuristicDebug -Source 'Security' -Message 'Analyzing autorun policy entries' -Data ([ordered]@{
                EntryCount = if ($autorunEntries) { $autorunEntries.Count } else { 0 }
            })

            $preferredPaths = @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            )

            $noDriveResult = Get-AutorunPolicyValue -Entries $autorunEntries -PreferredPaths $preferredPaths -Name 'NoDriveTypeAutoRun'
            $noAutoResult = Get-AutorunPolicyValue -Entries $autorunEntries -PreferredPaths $preferredPaths -Name 'NoAutoRun'
            $noDriveValue = if ($noDriveResult) { $noDriveResult.Value } else { $null }
            $noAutoValue = if ($noAutoResult) { $noAutoResult.Value } else { $null }
            $noDriveHardened = ($noDriveValue -eq 255)
            $noAutoHardened = ($noAutoValue -eq 1)

            $evidenceLines = [System.Collections.Generic.List[string]]::new()

            if ($noDriveResult) {
                if ($noDriveValue -ne $null) {
                    $evidenceLines.Add(("Effective NoDriveTypeAutoRun: 0x{0:X2} ({0}) from {1}" -f $noDriveValue, $noDriveResult.Path)) | Out-Null
                } elseif ($noDriveResult.RawValue) {
                    $evidenceLines.Add(("Effective NoDriveTypeAutoRun: value '{0}' from {1} could not be parsed" -f $noDriveResult.RawValue, $noDriveResult.Path)) | Out-Null
                } else {
                    $evidenceLines.Add('Effective NoDriveTypeAutoRun: value present but unreadable') | Out-Null
                }
            } else {
                $evidenceLines.Add('Effective NoDriveTypeAutoRun: not set (no applicable registry value found)') | Out-Null
            }

            if ($noAutoResult) {
                if ($noAutoValue -ne $null) {
                    $evidenceLines.Add(("Effective NoAutoRun: {0} from {1}" -f $noAutoValue, $noAutoResult.Path)) | Out-Null
                } elseif ($noAutoResult.RawValue) {
                    $evidenceLines.Add(("Effective NoAutoRun: value '{0}' from {1} could not be parsed" -f $noAutoResult.RawValue, $noAutoResult.Path)) | Out-Null
                } else {
                    $evidenceLines.Add('Effective NoAutoRun: value present but unreadable') | Out-Null
                }
            } else {
                $evidenceLines.Add('Effective NoAutoRun: not set (no applicable registry value found)') | Out-Null
            }

            foreach ($entry in (ConvertTo-List $autorunEntries)) {
                if (-not $entry) { continue }

                $lineParts = [System.Collections.Generic.List[string]]::new()
                if ($entry.Error) {
                    $lineParts.Add(("error: {0}" -f $entry.Error)) | Out-Null
                } elseif ($entry.PSObject.Properties['Exists'] -and -not $entry.Exists) {
                    $lineParts.Add('missing') | Out-Null
                } elseif (-not $entry.Values) {
                    $lineParts.Add('no values captured') | Out-Null
                } else {
                    foreach ($primary in @(
                        @{ Name = 'NoDriveTypeAutoRun'; Hex = $true },
                        @{ Name = 'NoAutoRun'; Hex = $false }
                    )) {
                        $property = $entry.Values.PSObject.Properties[$primary.Name]
                        if ($property) {
                            $converted = ConvertTo-NullablePolicyInt $property.Value
                            if ($primary.Hex -and $converted -ne $null) {
                                $lineParts.Add(("{0}=0x{1:X2} ({1})" -f $primary.Name, $converted)) | Out-Null
                            } elseif ($converted -ne $null) {
                                $lineParts.Add(("{0}={1}" -f $primary.Name, $converted)) | Out-Null
                            } else {
                                $lineParts.Add(("{0}={1}" -f $primary.Name, $property.Value)) | Out-Null
                            }
                        } else {
                            $lineParts.Add(("{0}=(not set)" -f $primary.Name)) | Out-Null
                        }
                    }

                    foreach ($extra in @('DisableAutoplay', 'DisableAutorun', 'Autorunsc', 'HonorAutorunSetting')) {
                        $extraProp = $entry.Values.PSObject.Properties[$extra]
                        if ($extraProp) {
                            $lineParts.Add(("{0}={1}" -f $extra, $extraProp.Value)) | Out-Null
                        }
                    }
                }

                $detail = if ($lineParts.Count -gt 0) { $lineParts -join '; ' } else { 'no relevant values' }
                $evidenceLines.Add(("Path {0}: {1}" -f $entry.Path, $detail)) | Out-Null
            }

            $evidenceText = $evidenceLines.ToArray() -join "`n"
            if ($noDriveHardened -and $noAutoHardened) {
                Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Autorun/Autoplay policies hardened.' -Evidence $evidenceText -Subcategory 'Autorun Policies' -CheckId 'Security/AutorunPolicies'
            } else {
                $statusParts = [System.Collections.Generic.List[string]]::new()
                if (-not $noDriveHardened) {
                    if ($noDriveValue -eq $null) {
                        $statusParts.Add('NoDriveTypeAutoRun missing') | Out-Null
                    } else {
                        $statusParts.Add(("NoDriveTypeAutoRun=0x{0:X2}" -f ($noDriveValue -band 0xFFFFFFFF))) | Out-Null
                    }
                }
                if (-not $noAutoHardened) {
                    if ($noAutoValue -eq $null) {
                        $statusParts.Add('NoAutoRun missing') | Out-Null
                    } else {
                        $statusParts.Add(("NoAutoRun={0}" -f $noAutoValue)) | Out-Null
                    }
                }
                $detailText = if ($statusParts.Count -gt 0) { $statusParts -join '; ' } else { 'values not hardened' }
                $title = "Autorun/Autoplay policies not hardened ({0}), allowing removable media autorun." -f $detailText
                Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title $title -Evidence $evidenceText -Subcategory 'Autorun Policies' -CheckId 'Security/AutorunPolicies'
            }
        } else {
            Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Autorun policy artifact missing expected structure, so removable media autorun defenses are unknown.' -Subcategory 'Autorun Policies'
        }
    } else {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'warning' -Title 'Autorun policy artifact not collected, so removable media autorun defenses are unknown.' -Subcategory 'Autorun Policies'
    }
}
