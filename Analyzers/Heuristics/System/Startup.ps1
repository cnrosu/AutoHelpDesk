function ConvertTo-StartupCollection {
    param([AllowNull()]$Value)

    $result = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Value) { return $result.ToArray() }

    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($entry in $Value.GetEnumerator()) {
            $result.Add($entry.Value) | Out-Null
        }

        return $result.ToArray()
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($item in $Value) {
            $result.Add($item) | Out-Null
        }

        return $result.ToArray()
    }

    $result.Add($Value) | Out-Null
    return $result.ToArray()
}

function New-StartupSourceDetail {
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Value
    )

    $ok = $null
    if ($Value -and $Value.PSObject.Properties['Ok']) {
        try { $ok = [bool]$Value.Ok } catch {}
    } elseif ($Value -and $Value.PSObject.Properties['Success']) {
        try { $ok = [bool]$Value.Success } catch {}
    } elseif ($Value -and $Value.PSObject.Properties['Status']) {
        $status = $Value.Status
        if ($status -is [bool]) { $ok = [bool]$status }
        elseif ($status -is [string]) {
            $normalized = $status.Trim().ToLowerInvariant()
            if ($normalized -in @('ok', 'true', 'success')) { $ok = $true }
            elseif ($normalized -in @('false', 'fail', 'error')) { $ok = $false }
        }
    }

    $count = $null
    foreach ($propertyName in @('Count', 'ItemCount', 'ItemsCount', 'Total', 'Found', 'EntryCount')) {
        if ($Value -and $Value.PSObject.Properties[$propertyName]) {
            try {
                $count = [int]$Value.PSObject.Properties[$propertyName].Value
                break
            } catch {}
        }
    }

    $errors = New-Object System.Collections.Generic.List[string]
    if ($Value) {
        foreach ($propertyName in @('Error', 'Errors', 'LastError')) {
            if (-not $Value.PSObject.Properties[$propertyName]) { continue }
            foreach ($errorEntry in (ConvertTo-StartupCollection -Value $Value.$propertyName)) {
                if ($errorEntry) { $errors.Add([string]$errorEntry) | Out-Null }
            }
        }
    }

    $items = $null
    foreach ($propertyName in @('Inventory', 'Items', 'Entries', 'StartupItems', 'StartupCommands')) {
        if ($Value -and $Value.PSObject.Properties[$propertyName]) {
            $items = $Value.PSObject.Properties[$propertyName].Value
            break
        }
    }

    if ($null -eq $count -and $null -ne $items) {
        $derivedItems = ConvertTo-StartupCollection -Value $items
        $count = $derivedItems.Count
    }

    $users = $null
    foreach ($propertyName in @('Users', 'Profiles', 'Sids')) {
        if ($Value -and $Value.PSObject.Properties[$propertyName]) {
            $users = $Value.PSObject.Properties[$propertyName].Value
            break
        }
    }

    return [pscustomobject]@{
        Name   = $Name
        Ok     = $ok
        Count  = $count
        Errors = $errors.ToArray()
        Users  = $users
        Items  = $items
        Raw    = $Value
    }
}

function Merge-StartupSourceDetail {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, System.Management.Automation.PSCustomObject]]$Map,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return }

    $detail = New-StartupSourceDetail -Name $Name -Value $Value
    if (-not $detail) { return }

    if ($Map.ContainsKey($Name)) {
        $existing = $Map[$Name]
        $shouldReplace = $false
        if ($existing.Ok -eq $null -and $detail.Ok -ne $null) { $shouldReplace = $true }
        elseif ($null -eq $existing.Count -and $null -ne $detail.Count) { $shouldReplace = $true }
        elseif (-not $existing.Items -and $detail.Items) { $shouldReplace = $true }
        elseif (($existing.Errors.Count -eq 0) -and ($detail.Errors.Count -gt 0)) { $shouldReplace = $true }
        elseif ($existing.Users -eq $null -and $detail.Users -ne $null) { $shouldReplace = $true }

        if ($shouldReplace) { $Map[$Name] = $detail }
    } else {
        $Map[$Name] = $detail
    }
}

function Get-StartupSourceDetails {
    param([AllowNull()]$Payload)

    $map = New-Object 'System.Collections.Generic.Dictionary[string, System.Management.Automation.PSCustomObject]' ([System.StringComparer]::OrdinalIgnoreCase)
    if (-not $Payload) { return @() }

    if ($Payload.PSObject.Properties['Sources']) {
        $sourcesValue = $Payload.Sources
        if ($sourcesValue -is [System.Collections.IDictionary]) {
            foreach ($entry in $sourcesValue.GetEnumerator()) {
                Merge-StartupSourceDetail -Map $map -Name ([string]$entry.Key) -Value $entry.Value
            }
        } else {
            foreach ($item in (ConvertTo-StartupCollection -Value $sourcesValue)) {
                if (-not $item) { continue }
                $name = $null
                foreach ($propertyName in @('Name', 'Source', 'Key', 'Id', 'Identifier')) {
                    if ($item.PSObject.Properties[$propertyName] -and $item.$propertyName) {
                        $name = [string]$item.$propertyName
                        break
                    }
                }

                if (-not $name -and ($item -is [string])) {
                    $name = [string]$item
                }

                if ($name) {
                    Merge-StartupSourceDetail -Map $map -Name $name -Value $item
                }
            }
        }
    }

    foreach ($name in @('RegistryHKLM', 'RegistryHKU', 'StartupFolders', 'ScheduledTasks', 'ServicesAuto')) {
        if ($Payload.PSObject.Properties[$name]) {
            Merge-StartupSourceDetail -Map $map -Name $name -Value $Payload.$name
        }
    }

    return $map.Values
}

function Get-StartupInventoryEntries {
    param(
        [AllowNull()]$Payload,
        [object[]]$Sources
    )

    $entries = New-Object System.Collections.Generic.List[object]
    $explicitInventory = $false

    if ($Payload) {
        foreach ($propertyName in @('Inventory', 'StartupCommands', 'StartupItems', 'Items', 'Entries')) {
            if (-not $Payload.PSObject.Properties[$propertyName]) { continue }
            $explicitInventory = $true
            foreach ($entry in (ConvertTo-StartupCollection -Value $Payload.PSObject.Properties[$propertyName].Value)) {
                if ($entry) { $entries.Add($entry) | Out-Null }
            }
        }
    }

    if ($explicitInventory) { return $entries.ToArray() }

    if ($Sources) {
        foreach ($source in $Sources) {
            if (-not $source) { continue }
            foreach ($entry in (ConvertTo-StartupCollection -Value $source.Items)) {
                if ($entry) { $entries.Add($entry) | Out-Null }
            }
        }
    }

    return $entries.ToArray()
}

function Test-StartupInventoryExplicitlyNull {
    param([AllowNull()]$Payload)

    if (-not $Payload) { return $false }

    foreach ($propertyName in @('Inventory', 'StartupCommands', 'StartupItems', 'Items', 'Entries')) {
        if ($Payload.PSObject.Properties[$propertyName] -and $null -eq $Payload.PSObject.Properties[$propertyName].Value) {
            return $true
        }
    }

    return $false
}

function Get-StartupCollectedAtUtc {
    param([AllowNull()]$Payload)

    if (-not $Payload) { return $null }

    foreach ($propertyName in @('CollectedAtUtc', 'CollectedUtc', 'CollectedAt', 'Collected')) {
        if ($Payload.PSObject.Properties[$propertyName] -and $Payload.$propertyName) {
            return [string]$Payload.$propertyName
        }
    }

    if ($Payload.PSObject.Properties['Metadata']) {
        $metadata = $Payload.Metadata
        foreach ($propertyName in @('CollectedAtUtc', 'CollectedUtc', 'CollectedAt', 'Collected')) {
            if ($metadata.PSObject.Properties[$propertyName] -and $metadata.$propertyName) {
                return [string]$metadata.$propertyName
            }
        }
    }

    return $null
}

function Get-StartupConsecutiveFailureCount {
    param([AllowNull()]$Payload)

    if (-not $Payload) { return $null }

    foreach ($propertyName in @('ConsecutiveFailures', 'ConsecutiveUnavailable', 'ConsecutiveCoverageFailures', 'ConsecutiveCollectorFailures')) {
        if ($Payload.PSObject.Properties[$propertyName]) {
            try { return [int]$Payload.$propertyName } catch {}
        }
    }

    if ($Payload.PSObject.Properties['State']) {
        $state = $Payload.State
        foreach ($propertyName in @('ConsecutiveFailures', 'ConsecutiveUnavailable', 'ConsecutiveCoverageFailures', 'ConsecutiveCollectorFailures')) {
            if ($state.PSObject.Properties[$propertyName]) {
                try { return [int]$state.$propertyName } catch {}
            }
        }
    }

    return $null
}

function Get-StartupUserCount {
    param([AllowNull()]$Users)

    if (-not $Users) { return $null }

    if ($Users -is [System.Collections.IDictionary]) {
        return [int]$Users.Count
    }

    $collection = ConvertTo-StartupCollection -Value $Users
    if ($collection.Count -gt 0) { return [int]$collection.Count }

    return $null
}

function Get-StartupSourceEvidenceSegments {
    param([object[]]$Sources)

    $segments = New-Object System.Collections.Generic.List[string]
    if (-not $Sources) { return $segments.ToArray() }

    foreach ($source in $Sources) {
        if (-not $source -or -not $source.Name) { continue }

        $status = if ($source.Ok -eq $true) { 'True' } elseif ($source.Ok -eq $false) { 'False' } else { 'Unknown' }

        $details = New-Object System.Collections.Generic.List[string]
        if ($null -ne $source.Count) {
            $details.Add(("Count={0}" -f $source.Count)) | Out-Null
        } elseif ($null -ne $source.Items) {
            $items = ConvertTo-StartupCollection -Value $source.Items
            $details.Add(("Count={0}" -f $items.Count)) | Out-Null
        }

        $userCount = Get-StartupUserCount -Users $source.Users
        if ($null -ne $userCount) {
            $details.Add(("Users={0}" -f $userCount)) | Out-Null
        }

        if ($source.Errors -and $source.Errors.Count -gt 0) {
            $details.Add(("Error={0}" -f $source.Errors[0])) | Out-Null
        } elseif ($source.Raw -and $source.Raw.PSObject.Properties['Error'] -and $source.Raw.Error) {
            $details.Add(("Error={0}" -f $source.Raw.Error)) | Out-Null
        }

        $detailText = if ($details.Count -gt 0) { " ({0})" -f ($details -join ', ') } else { '' }
        $segments.Add(("{0} Ok={1}{2}" -f $source.Name, $status, $detailText)) | Out-Null
    }

    return $segments.ToArray()
}

function Invoke-SystemStartupChecks {
    param(
        [Parameter(Mandatory)]
        $Context,
        [Parameter(Mandatory)]
        $Result
    )

    Write-HeuristicDebug -Source 'System/Startup' -Message 'Starting startup checks'

    $payload = $null
    $payloadSource = $null

    $startupArtifact = Get-AnalyzerArtifact -Context $Context -Name 'startup'
    Write-HeuristicDebug -Source 'System/Startup' -Message 'Resolved startup inventory artifact' -Data ([ordered]@{
        Found = [bool]$startupArtifact
    })
    if ($startupArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $startupArtifact)
        if ($payload) {
            $payloadSource = if ($payload.PSObject.Properties['Source']) { [string]$payload.Source } else { 'startup-collector' }
            Write-HeuristicDebug -Source 'System/Startup' -Message 'Loaded startup inventory payload' -Data ([ordered]@{
                Source     = $payloadSource
                Version    = if ($payload.PSObject.Properties['Version']) { [string]$payload.Version } else { $null }
                EntryCount = if ($payload.PSObject.Properties['StartupCommands'] -and $payload.StartupCommands) { (@($payload.StartupCommands | Where-Object { $_ })).Count } else { $null }
            })
        }
    }

    if (-not $payload) {
        $payload = Get-MsinfoStartupPayload -Context $Context
        if ($payload) {
            $payloadSource = 'msinfo32'
            Write-HeuristicDebug -Source 'System/Startup' -Message 'Loaded msinfo startup payload' -Data ([ordered]@{
                Source      = 'msinfo32'
                EntryCount  = if ($payload.StartupCommands) { (@($payload.StartupCommands | Where-Object { $_ })).Count } else { 0 }
                SectionName = if ($payload.PSObject.Properties['SectionName']) { [string]$payload.SectionName } else { $null }
            })
        }
    }

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Startup program inventory unavailable, so excess or missing autoruns that slow logins or indicate incomplete data cannot be assessed.' -Subcategory 'Startup Programs'
        return
    }

    $sources = @(Get-StartupSourceDetails -Payload $payload)
    $entries = @(Get-StartupInventoryEntries -Payload $payload -Sources $sources | Where-Object { $_ })
    $explicitNullInventory = Test-StartupInventoryExplicitlyNull -Payload $payload
    $collectedAtUtc = Get-StartupCollectedAtUtc -Payload $payload
    $coverageScore = $null
    if ($payload.PSObject.Properties['CoverageScore']) {
        try { $coverageScore = [int]$payload.CoverageScore } catch {}
    }
    if ($null -eq $coverageScore -and $sources.Count -gt 0) {
        $coverageScore = @($sources | Where-Object { $_.Ok -eq $true }).Count
    }

    if ($sources.Count -gt 0) {
        $sourceDebug = $sources | ForEach-Object {
            [ordered]@{
                Name  = $_.Name
                Ok    = $_.Ok
                Count = $_.Count
                Error = if ($_.Errors -and $_.Errors.Count -gt 0) { $_.Errors[0] } elseif ($_.Raw -and $_.Raw.PSObject.Properties['Error']) { $_.Raw.Error } else { $null }
            }
        }

        Write-HeuristicDebug -Source 'System/Startup' -Message 'Startup inventory source states' -Data ([ordered]@{
            CoverageScore = $coverageScore
            Sources       = $sourceDebug
        })
    }

    $hasCoverageMetadata = ($sources.Count -gt 0 -or $null -ne $coverageScore)
    if ($hasCoverageMetadata -and $null -ne $coverageScore -and $coverageScore -lt 3) {
        $sourceEvidence = Get-StartupSourceEvidenceSegments -Sources $sources
        $evidenceParts = New-Object System.Collections.Generic.List[string]
        if ($sourceEvidence.Count -gt 0) {
            $evidenceParts.Add(("Sources: {0}" -f ($sourceEvidence -join '; '))) | Out-Null
        }
        if ($collectedAtUtc) {
            $evidenceParts.Add(("CollectedAtUtc: {0}" -f $collectedAtUtc)) | Out-Null
        }

        $evidence = $evidenceParts -join "`n"

        $primaryNames = @('RegistryHKLM', 'RegistryHKU', 'StartupFolders', 'ScheduledTasks', 'ServicesAuto')
        $primarySources = foreach ($name in $primaryNames) {
            $match = $sources | Where-Object { $_.Name -and ($_.Name.ToString().ToLowerInvariant() -eq $name.ToLowerInvariant()) } | Select-Object -First 1
            if ($match) { $match }
        }

        $failedPrimary = @($primarySources | Where-Object { $_ -and $_.Ok -ne $true })
        $allPrimaryFailed = ($primarySources.Count -gt 0 -and $failedPrimary.Count -eq $primarySources.Count)
        $consecutiveFailures = Get-StartupConsecutiveFailureCount -Payload $payload

        if ($allPrimaryFailed -and ($entries.Count -eq 0 -or $explicitNullInventory) -and $consecutiveFailures -ne $null -and $consecutiveFailures -ge 2) {
            $title = 'Startup inventory collection repeatedly failed, so autoruns remain unknown.'
            Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
            return
        }

        if ($failedPrimary.Count -ge 2) {
            $failedNames = ($failedPrimary | ForEach-Object { $_.Name }) -join ', '
            $title = "Startup inventory collector failure: {0} returned errors." -f $failedNames
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
            return
        }

        $title = 'Startup program inventory unavailable, so excess or missing autoruns that slow logins or indicate incomplete data cannot be assessed.'
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title $title -Evidence $evidence -Subcategory 'Startup Programs'
        return
    }

    if ($entries -and $entries.Count -gt 0) {
        $entries = @($entries)
        if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) {
            $entries = @($entries)
        }

        $entries = @($entries)
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
    } elseif ($explicitNullInventory) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'Startup program inventory empty, so missing autoruns that slow logins or indicate incomplete data cannot be reviewed.' -Subcategory 'Startup Programs'
    }
}
