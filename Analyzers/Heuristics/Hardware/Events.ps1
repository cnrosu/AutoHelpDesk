function Get-SystemEventEntries {
    param($Context)

    $events = @()
    if (-not $Context) { return $events }

    $eventsArtifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
    if (-not $eventsArtifact) { return $events }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $eventsArtifact)
    if (-not $payload) { return $events }

    if (-not $payload.PSObject.Properties['System']) { return $events }

    $systemEntries = $payload.System
    if (-not $systemEntries) { return $events }

    if ($systemEntries -is [System.Collections.IEnumerable] -and -not ($systemEntries -is [string])) {
        foreach ($entry in $systemEntries) {
            if (-not $entry) { continue }
            if ($entry.PSObject.Properties['Error'] -and $entry.Error) { continue }
            $events += ,$entry
        }
    } else {
        if (-not ($systemEntries.PSObject.Properties['Error'] -and $systemEntries.Error)) {
            $events = @($systemEntries)
        }
    }

    return $events
}

function Get-DriverFailureEventMap {
    param($Context)

    $map = @{}
    $events = Get-SystemEventEntries -Context $Context
    if (-not $events -or $events.Count -eq 0) { return $map }

    foreach ($event in $events) {
        if (-not $event) { continue }

        $id = $null
        if ($event.PSObject.Properties['Id']) {
            $id = $event.Id
        }

        if ($null -eq $id) { continue }
        if ($id -notin 7000, 7001, 7026) { continue }

        $message = $null
        if ($event.PSObject.Properties['Message']) {
            $message = [string]$event.Message
        }

        $provider = $null
        if ($event.PSObject.Properties['ProviderName']) {
            $provider = [string]$event.ProviderName
        }

        $names = [System.Collections.Generic.List[string]]::new()

        if ($id -eq 7026) {
            if ($message) {
                $match = [regex]::Match($message, 'failed to load:\\s*(?<names>.+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)
                if ($match.Success) {
                    $list = $match.Groups['names'].Value
                    if ($list) {
                        $tokens = $list -split '[\\r\\n,;]+'
                        foreach ($token in $tokens) {
                            if ([string]::IsNullOrWhiteSpace($token)) { continue }
                            $names.Add($token.Trim()) | Out-Null
                        }
                    }
                }
            }
        } elseif ($id -eq 7001) {
            if ($message) {
                $match = [regex]::Match($message, '^The\\s+(?<primary>.+?)\\s+(?:service|driver)\\s+depends\\s+on\\s+the\\s+(?<dependency>.+?)\\s+(?:service|driver)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($match.Success) {
                    foreach ($groupName in @('primary','dependency')) {
                        $value = $match.Groups[$groupName].Value
                        if ($value) { $names.Add($value.Trim()) | Out-Null }
                    }
                } else {
                    $match = [regex]::Match($message, '^The\\s+(?<name>.+?)\\s+(?:service|driver)\\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    if ($match.Success) {
                        $value = $match.Groups['name'].Value
                        if ($value) { $names.Add($value.Trim()) | Out-Null }
                    }
                }
            }
        } else {
            if ($message) {
                $match = [regex]::Match($message, '^The\\s+(?<name>.+?)\\s+(?:service|driver)\\s+failed\\s+to\\s+start', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($match.Success) {
                    $value = $match.Groups['name'].Value
                    if ($value) { $names.Add($value.Trim()) | Out-Null }
                }
            }
        }

        if ($names.Count -eq 0) { continue }

        $time = $null
        if ($event.PSObject.Properties['TimeCreated']) {
            $time = $event.TimeCreated
        }

        foreach ($rawName in $names) {
            if ([string]::IsNullOrWhiteSpace($rawName)) { continue }

            $variants = [System.Collections.Generic.List[string]]::new()
            $lookup = @{}
            Add-UniqueDriverNameVariant -List $variants -Lookup $lookup -Name $rawName

            foreach ($variant in $variants) {
                if (-not $variant) { continue }
                $key = $variant.ToLowerInvariant()
                if (-not $map.ContainsKey($key)) {
                    $map[$key] = New-Object System.Collections.Generic.List[pscustomobject]
                }

                $map[$key].Add([pscustomobject]@{
                    Id          = $id
                    TimeCreated = $time
                    Message     = $message
                    Provider    = $provider
                }) | Out-Null
            }
        }
    }

    return $map
}

function Find-DriverFailureEvents {
    param(
        [string[]]$Candidates,
        [hashtable]$Map
    )

    $results = New-Object System.Collections.Generic.List[pscustomobject]
    if (-not $Candidates) { return $results.ToArray() }
    if (-not $Map) { return $results.ToArray() }

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $key = $candidate.ToLowerInvariant()
        if (-not $Map.ContainsKey($key)) { continue }

        foreach ($event in $Map[$key]) {
            if ($event) {
                $results.Add($event) | Out-Null
            }
        }
    }

    if ($results.Count -eq 0) { return $results.ToArray() }

    return ($results.ToArray() | Sort-Object -Property TimeCreated -Descending)
}

function Format-DriverFailureEvidence {
    param([pscustomobject[]]$Events)

    if (-not $Events -or $Events.Count -eq 0) { return $null }

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($event in ($Events | Select-Object -First 3)) {
        if (-not $event) { continue }
        $time = if ($event.TimeCreated) { [string]$event.TimeCreated } else { 'Unknown time' }
        $message = if ($event.Message) { [regex]::Replace([string]$event.Message, '\\s+', ' ') } else { 'No message provided' }
        $lines.Add(("Event {0} at {1}: {2}" -f $event.Id, $time, $message.Trim())) | Out-Null
    }

    if ($lines.Count -eq 0) { return $null }
    return ($lines.ToArray() -join "`n")
}
