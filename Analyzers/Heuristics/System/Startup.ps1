function Invoke-SystemStartupChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Startup' -Message 'Starting startup checks'

    $entryCount = 0
    $inventorySource = $null
    $msinfoStatus = 'unknown'
    $fallbackStatus = 'not-attempted'
    $fallbackErrors = New-Object System.Collections.Generic.List[string]

    $payload = Get-MsinfoStartupPayload -Context $Context
    if ($payload) {
        $msinfoStatus = 'populated'
        if ($payload.PSObject.Properties['StartupCommands'] -and $null -ne $payload.StartupCommands) {
            $entryCount = (@($payload.StartupCommands | Where-Object { $_ })).Count
        }
        $inventorySource = 'msinfo32'
        Write-HeuristicDebug -Source 'System/Startup' -Message 'Loaded msinfo startup payload' -Data ([ordered]@{
            Source      = $inventorySource
            EntryCount  = $entryCount
            SectionName = if ($payload.PSObject.Properties['SectionName']) { [string]$payload.SectionName } else { $null }
        })
    } else {
        $msinfoStatus = 'missing-or-empty'
        $startupArtifact = Get-AnalyzerArtifact -Context $Context -Name 'startup'
        Write-HeuristicDebug -Source 'System/Startup' -Message 'Resolved legacy startup artifact' -Data ([ordered]@{
            Found = [bool]$startupArtifact
        })
        if ($startupArtifact) {
            $fallbackStatus = 'artifact-found'
            $artifactPayload = Get-ArtifactPayload -Artifact $startupArtifact
            $payload = Resolve-SinglePayload -Payload $artifactPayload

            $payloadsToInspect = @()
            if ($artifactPayload -is [System.Collections.IEnumerable] -and -not ($artifactPayload -is [string])) {
                $payloadsToInspect = @($artifactPayload | Where-Object { $_ })
            } elseif ($null -ne $artifactPayload) {
                $payloadsToInspect = @($artifactPayload)
            }

            foreach ($candidatePayload in $payloadsToInspect) {
                if (-not $candidatePayload) { continue }
                if ($candidatePayload.PSObject.Properties['CollectionErrors'] -and $candidatePayload.CollectionErrors) {
                    foreach ($error in @($candidatePayload.CollectionErrors)) {
                        if ([string]::IsNullOrWhiteSpace($error)) { continue }
                        $fallbackErrors.Add([string]$error) | Out-Null
                    }
                }
            }

            if ($payload) {
                $fallbackStatus = 'resolved'
                if ($payload.PSObject.Properties['StartupCommands'] -and $null -ne $payload.StartupCommands) {
                    $entryCount = (@($payload.StartupCommands | Where-Object { $_ })).Count
                }
                $inventorySource = if ($payload.PSObject.Properties['Source'] -and $payload.Source) { [string]$payload.Source } else { 'collector' }
                Write-HeuristicDebug -Source 'System/Startup' -Message 'Loaded startup payload from collector fallback' -Data ([ordered]@{
                    Source      = $inventorySource
                    EntryCount  = $entryCount
                    ErrorCount  = $fallbackErrors.Count
                })
            } else {
                if ($artifactPayload) {
                    $fallbackStatus = 'no-payload'
                } else {
                    $fallbackStatus = 'artifact-empty'
                }
            }
        } else {
            $fallbackStatus = 'artifact-missing'
        }
    }

    if ($payload -and -not $inventorySource) {
        if ($payload.PSObject.Properties['Source'] -and $payload.Source) {
            $inventorySource = [string]$payload.Source
        } else {
            $inventorySource = 'collector'
        }
    }

    if (-not $payload) {
        $evidenceParts = New-Object System.Collections.Generic.List[string]

        if ($msinfoStatus -eq 'missing-or-empty') {
            $evidenceParts.Add('msinfo32 startup section was missing or empty in the collected report.') | Out-Null
        }

        switch ($fallbackStatus) {
            'artifact-missing' {
                $evidenceParts.Add('Win32_StartupCommand fallback artifact was not collected.') | Out-Null
            }
            'artifact-empty' {
                $evidenceParts.Add('Win32_StartupCommand fallback artifact existed but contained no payload data.') | Out-Null
            }
            'no-payload' {
                $evidenceParts.Add('Win32_StartupCommand fallback artifact could not be parsed into a payload.') | Out-Null
            }
        }

        if ($fallbackErrors.Count -gt 0) {
            $evidenceParts.Add('Collector reported errors: ' + ($fallbackErrors -join '; ')) | Out-Null
        }

        $evidence = if ($evidenceParts.Count -gt 0) { $evidenceParts -join ' ' } else { 'Diagnostics package did not include startup inventory data from msinfo32 or Win32_StartupCommand.' }

        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Startup program inventory unavailable, so excess or missing autoruns that slow logins or indicate incomplete data cannot be assessed.' -Evidence $evidence -Subcategory 'Startup Programs'
        return
    }

    $startupProperty = $null
    $startupCommands = $null
    if ($payload) {
        $startupProperty = $payload.PSObject.Properties['StartupCommands']
        if ($startupProperty) {
            $startupCommands = $payload.StartupCommands
        }
    }

    if ($startupProperty) {
        $sourceLabelForCheck = if ($inventorySource) { $inventorySource } elseif ($payload.PSObject.Properties['Source'] -and $payload.Source) { [string]$payload.Source } else { 'unknown' }
        $checkStatus = '{0} ({1} entries)' -f $sourceLabelForCheck, $entryCount
        Add-CategoryCheck -CategoryResult $Result -Name 'Startup inventory source' -Status $checkStatus

        $entries = @()
        $hasValue = $false

        if ($startupCommands -is [System.Collections.IEnumerable] -and -not ($startupCommands -is [string])) {
            $entries = @($startupCommands)
            $hasValue = $true
        } elseif ($null -ne $startupCommands) {
            $entries = @($startupCommands)
            $hasValue = $true
        }

        $entries = @($entries | Where-Object { $_ })

        if ($hasValue) {
            $errorEntries = @($entries | Where-Object { $_.PSObject.Properties['Error'] -and $_.Error })
            if ($errorEntries.Count -gt 0) {
                $message = "Unable to enumerate all startup items ({0})." -f ($errorEntries[0].Error)
                Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Startup program inventory incomplete, so excess or missing autoruns that slow logins or indicate incomplete data may be overlooked.' -Evidence $message -Subcategory 'Startup Programs'
            }

            $validEntries = @($entries | Where-Object { -not ($_.PSObject.Properties['Error'] -and $_.Error) })
            if ($validEntries.Count -gt 0) {
                $nonMicrosoftEntries = @($validEntries | Where-Object { -not (Test-IsMicrosoftStartupEntry $_) })

                Add-CategoryCheck -CategoryResult $Result -Name 'Startup entries detected' -Status ([string]$validEntries.Count)
                Add-CategoryCheck -CategoryResult $Result -Name 'Startup entries (non-Microsoft)' -Status ([string]$nonMicrosoftEntries.Count)

                $evidenceBuilder = New-Object System.Collections.Generic.List[string]
                [void]$evidenceBuilder.Add("Total startup entries evaluated: {0}" -f $validEntries.Count)
                [void]$evidenceBuilder.Add("Non-Microsoft startup entries: {0}" -f $nonMicrosoftEntries.Count)

                foreach ($entry in $nonMicrosoftEntries) {
                    $parts = New-Object System.Collections.Generic.List[string]
                    if ($entry.Name) { [void]$parts.Add([string]$entry.Name) }
                    if ($entry.Command) { [void]$parts.Add([string]$entry.Command) }
                    if ($entry.Location) { [void]$parts.Add(("Location: {0}" -f $entry.Location)) }
                    if ($entry.User) { [void]$parts.Add(("User: {0}" -f $entry.User)) }
                    $line = ($parts -join ' | ')
                    if ($line) { [void]$evidenceBuilder.Add($line) }
                }

                $evidence = $evidenceBuilder -join "`n"

                if ($nonMicrosoftEntries.Count -gt 10) {
                    $title = "Startup autoruns bloat: {0} non-Microsoft entries detected, which can slow logins or hide issues. Review and trim startup apps to reduce login delay." -f $nonMicrosoftEntries.Count
                    Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
                } elseif ($nonMicrosoftEntries.Count -gt 5) {
                    $title = "Startup autoruns trending high ({0} non-Microsoft entries), which can slow logins or hide issues." -f $nonMicrosoftEntries.Count
                    Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
                } else {
                    $title = "Startup autoruns manageable ({0} non-Microsoft of {1} total)." -f $nonMicrosoftEntries.Count, $validEntries.Count
                    Add-CategoryNormal -CategoryResult $Result -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
                }
            } else {
                Add-CategoryNormal -CategoryResult $Result -Title 'No startup entries detected' -Subcategory 'Startup Programs'
            }
        } else {
            Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Startup program inventory empty, so missing autoruns that slow logins or indicate incomplete data cannot be reviewed.' -Subcategory 'Startup Programs'
        }
    }
}
