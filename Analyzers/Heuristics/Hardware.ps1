<#!
.SYNOPSIS
    Hardware heuristics evaluating Device Manager driver health and startup state.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-HardwareDriverText {
    param(
        $Value
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [pscustomobject]) {
        if ($Value.PSObject.Properties['Error'] -and $Value.Error) {
            return $null
        }
        if ($Value.PSObject.Properties['Value'] -and $Value.Value) {
            return [string]$Value.Value
        }
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $builder = [System.Text.StringBuilder]::new()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $text = [string]$item
            if ($builder.Length -gt 0) { $null = $builder.AppendLine() }
            $null = $builder.Append($text)
        }
        return $builder.ToString()
    }

    return [string]$Value
}

function Parse-DriverQueryEntries {
    param(
        [string]$Text
    )

    $entries = New-Object System.Collections.Generic.List[pscustomobject]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $entries.ToArray() }

    $lines = [regex]::Split($Text, '\r?\n')
    $current = [ordered]@{}

    foreach ($line in $lines) {
        if ($null -eq $line) { continue }
        $trimmed = $line.TrimEnd()
        if (-not $trimmed) {
            if ($current.Count -gt 0) {
                $entries.Add([pscustomobject]$current) | Out-Null
                $current = [ordered]@{}
            }
            continue
        }

        $match = [regex]::Match($trimmed, '^(?<key>[^:]+?):\s*(?<value>.*)$')
        if ($match.Success) {
            $key = $match.Groups['key'].Value.Trim()
            $value = $match.Groups['value'].Value
            if ($null -ne $value) { $value = $value.Trim() }

            if (-not $current.Contains($key)) {
                $current[$key] = $value
            } else {
                $existing = $current[$key]
                if ($existing -is [System.Collections.IEnumerable] -and -not ($existing -is [string])) {
                    $items = New-Object System.Collections.Generic.List[object]
                    foreach ($item in $existing) { $items.Add($item) | Out-Null }
                    $items.Add($value) | Out-Null
                    $current[$key] = $items.ToArray()
                } else {
                    $current[$key] = @($existing, $value)
                }
            }
            continue
        }

        if ($current.Count -gt 0) {
            $keysArray = @($current.Keys)
            if ($keysArray.Count -gt 0) {
                $lastKey = $keysArray[$keysArray.Count - 1]
                $existingValue = $current[$lastKey]
                $addition = $trimmed.Trim()
                if ($existingValue -is [System.Collections.IEnumerable] -and -not ($existingValue -is [string])) {
                    $lastIndex = $existingValue.Count - 1
                    if ($lastIndex -ge 0) {
                        $existingValue[$lastIndex] = ("{0} {1}" -f $existingValue[$lastIndex], $addition).Trim()
                    }
                } else {
                    $current[$lastKey] = ("{0} {1}" -f $existingValue, $addition).Trim()
                }
            }
        }
    }

    if ($current.Count -gt 0) {
        $entries.Add([pscustomobject]$current) | Out-Null
    }

    return $entries.ToArray()
}

function Get-DriverPropertyValue {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $Entry.PSObject.Properties[$name]
        if (-not $prop) { continue }
        $raw = $prop.Value
        if ($null -eq $raw) { continue }

        if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
            $values = New-Object System.Collections.Generic.List[string]
            foreach ($item in $raw) {
                if ($null -eq $item) { continue }
                $text = [string]$item
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    $values.Add($text.Trim()) | Out-Null
                }
            }
            if ($values.Count -gt 0) {
                return ($values.ToArray() -join '; ')
            }
        } else {
            $text = [string]$raw
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                return $text.Trim()
            }
        }
    }

    return $null
}

function Get-DriverLabel {
    param($Entry)

    $label = Get-DriverPropertyValue -Entry $Entry -Names @('Display Name','Module Name','Driver Name','Name')
    if ($label) { return $label }
    return 'Unknown driver'
}

function Get-DriverEvidence {
    param($Entry)

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('Display Name','Module Name','Driver Type','Start Mode','State','Status','Error Control','Path','Image Path','Link Date')) {
        $value = Get-DriverPropertyValue -Entry $Entry -Names @($name)
        if ($value) {
            $lines.Add(("{0}: {1}" -f $name, $value)) | Out-Null
        }
    }

    if ($lines.Count -eq 0) { return $null }
    return ($lines.ToArray() -join "`n")
}

function Normalize-DriverStatus {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -eq 'ok' -or $lower -eq 'okay') { return 'ok' }
    if ($lower -match 'error|fail|problem|fault') { return 'error' }
    if ($lower -match 'degrad|warn|issue') { return 'degraded' }
    if ($lower -match 'unknown|n/a|na') { return 'unknown' }
    return 'other'
}

function Normalize-DriverState {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -like 'run*') { return 'running' }
    if ($lower -like 'stop*') { return 'stopped' }
    if ($lower -like 'start*pend*') { return 'pending' }
    if ($lower -like 'pause*') { return 'paused' }
    return 'other'
}

function Normalize-DriverStartMode {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -match 'boot') { return 'boot' }
    if ($lower -match 'system') { return 'system' }
    if ($lower -match 'auto') { return 'auto' }
    if ($lower -match 'manual') { return 'manual' }
    if ($lower -match 'disabled|disable') { return 'disabled' }
    return 'other'
}

function Normalize-DriverErrorControl {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -match 'critical') { return 'critical' }
    if ($lower -match 'normal') { return 'normal' }
    if ($lower -match 'ignore') { return 'ignore' }
    return 'other'
}

function Invoke-HardwareHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Hardware' -Message 'Starting hardware heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Hardware'

    $driversArtifact = Get-AnalyzerArtifact -Context $Context -Name 'drivers'
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver artifact' -Data ([ordered]@{
        Found = [bool]$driversArtifact
    })

    if (-not $driversArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory artifact missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $driversArtifact)
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved driver payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory payload missing, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    if ($payload.DriverQuery -and $payload.DriverQuery.PSObject.Properties['Error'] -and $payload.DriverQuery.Error) {
        $source = if ($payload.DriverQuery.PSObject.Properties['Source']) { [string]$payload.DriverQuery.Source } else { 'driverquery.exe' }
        $evidence = if ($payload.DriverQuery.Error) { [string]$payload.DriverQuery.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
        return $result
    }

    $driverText = ConvertTo-HardwareDriverText -Value $payload.DriverQuery
    Write-HeuristicDebug -Source 'Hardware' -Message 'Driver query text resolved' -Data ([ordered]@{
        HasText = [bool]$driverText
        Length  = if ($driverText) { $driverText.Length } else { 0 }
    })

    if (-not $driverText) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory empty, so Device Manager issues can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    $entries = Parse-DriverQueryEntries -Text $driverText
    Write-HeuristicDebug -Source 'Hardware' -Message 'Parsed driver inventory entries' -Data ([ordered]@{
        EntryCount = $entries.Count
    })

    if ($entries.Count -eq 0) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Driver inventory could not be parsed, so Device Manager issues may be hidden." -Subcategory 'Collection'
        return $result
    }

    $issueCount = 0
    foreach ($entry in $entries) {
        if (-not $entry) { continue }

        $label = Get-DriverLabel -Entry $entry
        $statusRaw = Get-DriverPropertyValue -Entry $entry -Names @('Status')
        $statusNormalized = Normalize-DriverStatus -Value $statusRaw
        if ($statusNormalized -and $statusNormalized -ne 'ok' -and $statusNormalized -ne 'unknown') {
            $severity = switch ($statusNormalized) {
                'error'    { 'high' }
                'degraded' { 'medium' }
                default    { 'info' }
            }
            $title = if ($statusRaw) {
                "Driver status '{0}' reported for {1}, so the device may malfunction." -f $statusRaw, $label
            } else {
                "Driver status indicates an issue for {0}, so the device may malfunction." -f $label
            }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence (Get-DriverEvidence -Entry $entry) -Subcategory 'Device Manager'
            $issueCount++
        }

        $stateRaw = Get-DriverPropertyValue -Entry $entry -Names @('State')
        $startModeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Start Mode','StartMode')
        $stateNormalized = Normalize-DriverState -Value $stateRaw
        $startModeNormalized = Normalize-DriverStartMode -Value $startModeRaw
        if ($startModeNormalized -in @('boot','system','auto') -and $stateNormalized -ne 'running' -and $stateNormalized -ne 'pending') {
            $severity = if ($startModeNormalized -in @('boot','system')) { 'high' } else { 'medium' }
            $errorControlRaw = Get-DriverPropertyValue -Entry $entry -Names @('Error Control','ErrorControl')
            $errorControlNormalized = Normalize-DriverErrorControl -Value $errorControlRaw
            if ($errorControlNormalized -eq 'critical') { $severity = 'critical' }

            $title = if ($stateRaw -and $startModeRaw) {
                "Driver {0} is {1} despite start mode {2}, so hardware may not initialize." -f $label, $stateRaw, $startModeRaw
            } elseif ($startModeRaw) {
                "Driver {0} is not running despite start mode {1}, so hardware may not initialize." -f $label, $startModeRaw
            } else {
                "Driver {0} is not running despite an automatic start mode, so hardware may not initialize." -f $label
            }

            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence (Get-DriverEvidence -Entry $entry) -Subcategory 'Device Manager'
            $issueCount++
        }
    }

    Write-HeuristicDebug -Source 'Hardware' -Message 'Device Manager analysis completed' -Data ([ordered]@{
        IssuesRaised = $issueCount
    })

    if ($issueCount -eq 0) {
        Add-CategoryNormal -CategoryResult $result -Title 'Device Manager reports all drivers healthy.' -Subcategory 'Device Manager'
    }

    return $result
}
