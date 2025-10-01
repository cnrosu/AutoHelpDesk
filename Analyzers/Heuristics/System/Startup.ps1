function Invoke-SystemStartupChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Startup' -Message 'Starting startup checks'

    $startupArtifact = Get-AnalyzerArtifact -Context $Context -Name 'startup'
    Write-HeuristicDebug -Source 'System/Startup' -Message 'Resolved startup artifact' -Data ([ordered]@{
        Found = [bool]$startupArtifact
    })
    if (-not $startupArtifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Startup program artifact missing' -Subcategory 'Startup Programs'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $startupArtifact)
    Write-HeuristicDebug -Source 'System/Startup' -Message 'Evaluating startup payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if (-not $payload) { return }

    if ($payload -and $payload.StartupCommands) {
        $entries = $payload.StartupCommands
        if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) {
            $entries = @($entries)
        }

        $entries = @($entries)
        $errorEntries = @($entries | Where-Object { $_.PSObject.Properties['Error'] -and $_.Error })
        if ($errorEntries.Count -gt 0) {
            $message = "Unable to enumerate all startup items ({0})." -f ($errorEntries[0].Error)
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Startup program inventory incomplete' -Evidence $message -Subcategory 'Startup Programs'
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
                $title = "Startup autoruns bloat: {0} non-Microsoft entries detected. Review and trim startup apps to reduce login delay." -f $nonMicrosoftEntries.Count
                Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
            } elseif ($nonMicrosoftEntries.Count -gt 5) {
                $title = "Startup autoruns trending high ({0} non-Microsoft entries)." -f $nonMicrosoftEntries.Count
                Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
            } else {
                $title = "Startup autoruns manageable ({0} non-Microsoft of {1} total)." -f $nonMicrosoftEntries.Count, $validEntries.Count
                Add-CategoryNormal -CategoryResult $Result -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
            }
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'No startup entries detected' -Subcategory 'Startup Programs'
        }
    } elseif ($payload -and $payload.StartupCommands -eq $null) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Startup program inventory empty' -Subcategory 'Startup Programs'
    }
}
