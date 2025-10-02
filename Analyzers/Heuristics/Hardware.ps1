<#!
.SYNOPSIS
    Hardware heuristics evaluating Device Manager driver health and startup state.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function ConvertTo-AutorunInt {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return if ($Value) { 1 } else { 0 } }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) {
        return [int64]$Value
    }

    if ($Value -is [string]) {
        $trimmed = $Value.Trim()
        if (-not $trimmed) { return $null }

        if ($trimmed -match '^(?i:true|false)$') {
            return if ($trimmed -match '^(?i:true)$') { 1 } else { 0 }
        }

        if ($trimmed -match '^0x[0-9a-fA-F]+$') {
            try {
                return [int64]([Convert]::ToUInt64($trimmed.Substring(2), 16))
            } catch {
                return $null
            }
        }

        $parsed = 0
        if ([int64]::TryParse($trimmed, [ref]$parsed)) {
            return $parsed
        }
    }

    return $null
}

function Format-AutorunValueText {
    param($Value)

    if ($null -eq $Value) { return 'not set' }

    $numeric = ConvertTo-AutorunInt -Value $Value
    if ($null -ne $numeric) {
        try {
            $hex = [Convert]::ToUInt32($numeric).ToString('X')
            return ('{0} (0x{1})' -f $numeric, $hex)
        } catch {
            return [string]$numeric
        }
    }

    return [string]$Value
}

function Get-AutorunEntries {
    param($Payload)

    $entries = @()
    if (-not $Payload -or -not $Payload.PSObject.Properties['Registry']) { return $entries }

    foreach ($snapshot in @($Payload.Registry)) {
        if (-not $snapshot) { continue }

        $normalized = [ordered]@{}
        if ($snapshot.PSObject.Properties['Path'] -and $snapshot.Path) {
            $normalized.Path = [string]$snapshot.Path
        }
        if ($snapshot.PSObject.Properties['Error'] -and $snapshot.Error) {
            $normalized.Error = [string]$snapshot.Error
        }

        $values = @{}
        if ($snapshot.PSObject.Properties['Values'] -and $snapshot.Values) {
            foreach ($prop in $snapshot.Values.PSObject.Properties) {
                $values[$prop.Name] = $prop.Value
            }
        }
        if ($values.Count -gt 0) {
            $normalized.Values = [pscustomobject]$values
        }

        $entries += ,([pscustomobject]$normalized)
    }

    return $entries
}

function Get-AutorunEffectiveSetting {
    param(
        [pscustomobject[]]$Entries,
        [string[]]$Names
    )

    if (-not $Entries) { return $null }
    if (-not $Names -or $Names.Count -eq 0) { return $null }

    $priority = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    foreach ($path in $priority) {
        $entry = $Entries | Where-Object { $_ -and $_.Path -eq $path } | Select-Object -First 1
        if (-not $entry -or $entry.Error) { continue }
        if (-not ($entry.PSObject.Properties['Values'] -and $entry.Values)) { continue }
        foreach ($name in $Names) {
            if (-not $name) { continue }
            if ($entry.Values.PSObject.Properties[$name]) {
                return [pscustomobject]@{
                    Path  = $entry.Path
                    Name  = $name
                    Value = $entry.Values.$name
                }
            }
        }
    }

    return $null
}

function Build-AutorunEvidence {
    param(
        [pscustomobject[]]$Entries,
        [string[]]$Names
    )

    $lines = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $Entries) {
        if (-not $entry) { continue }

        $path = if ($entry.Path) { $entry.Path } else { '(unknown path)' }

        if ($entry.Error) {
            $lines.Add(("{0}: ERROR - {1}" -f $path, $entry.Error)) | Out-Null
            continue
        }

        if (-not ($entry.PSObject.Properties['Values'] -and $entry.Values)) {
            $lines.Add(("{0}: (no values captured)" -f $path)) | Out-Null
            continue
        }

        foreach ($name in $Names) {
            $value = $null
            if ($entry.Values.PSObject.Properties[$name]) { $value = $entry.Values.$name }
            $lines.Add(("{0}::{1} = {2}" -f $path, $name, (Format-AutorunValueText -Value $value))) | Out-Null
        }
    }

    if ($lines.Count -eq 0) { return $null }
    return ($lines.ToArray() -join "`n")
}

function Get-AutorunSettingSummary {
    param($Setting)

    if (-not $Setting -or -not $Setting.PSObject.Properties['Value']) { return 'not configured' }
    if ($null -eq $Setting.Value) { return 'not configured' }

    return Format-AutorunValueText -Value $Setting.Value
}

function Invoke-AutorunPolicyAssessment {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $CategoryResult
    )

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'autorun'
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved autorun artifact' -Data ([ordered]@{
        Found = [bool]$artifact
    })

    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title "Autorun policy artifact missing, so removable media settings can't be evaluated." -Subcategory 'Removable Media'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved autorun payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })

    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title "Autorun policy payload missing, so removable media settings can't be evaluated." -Subcategory 'Removable Media'
        return
    }

    $entries = Get-AutorunEntries -Payload $payload
    $entryCount = if ($entries) { $entries.Count } else { 0 }
    Write-HeuristicDebug -Source 'Hardware' -Message 'Parsed autorun registry entries' -Data ([ordered]@{
        EntryCount = $entryCount
    })

    if ($entryCount -eq 0) {
        Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'info' -Title "Autorun policy registry data missing, so removable media settings can't be evaluated." -Subcategory 'Removable Media'
        return
    }

    $driveSetting = Get-AutorunEffectiveSetting -Entries $entries -Names @('NoDriveTypeAutoRun')
    $autorunSetting = Get-AutorunEffectiveSetting -Entries $entries -Names @('NoAutoRun', 'NoAutorun')

    $driveNumeric = if ($driveSetting) { ConvertTo-AutorunInt -Value $driveSetting.Value } else { $null }
    $autorunNumeric = if ($autorunSetting) { ConvertTo-AutorunInt -Value $autorunSetting.Value } else { $null }

    $driveCompliant = ($null -ne $driveNumeric -and $driveNumeric -eq 255)
    $autorunCompliant = ($null -ne $autorunNumeric -and $autorunNumeric -eq 1)

    Write-HeuristicDebug -Source 'Hardware' -Message 'Evaluated autorun hardening posture' -Data ([ordered]@{
        DriveSetting       = Get-AutorunSettingSummary -Setting $driveSetting
        AutorunSetting     = Get-AutorunSettingSummary -Setting $autorunSetting
        DriveCompliant     = $driveCompliant
        AutorunCompliant   = $autorunCompliant
    })

    $effectiveLines = [System.Collections.Generic.List[string]]::new()
    $driveName = if ($driveSetting -and $driveSetting.Name) { $driveSetting.Name } else { 'NoDriveTypeAutoRun' }
    $autorunName = if ($autorunSetting -and $autorunSetting.Name) { $autorunSetting.Name } else { 'NoAutoRun' }
    $effectiveLines.Add(("{0}: {1}{2}" -f $driveName, (Get-AutorunSettingSummary -Setting $driveSetting),
        if ($driveSetting -and $driveSetting.Path) { " (from $($driveSetting.Path))" } else { '' })) | Out-Null
    $effectiveLines.Add(("{0}: {1}{2}" -f $autorunName, (Get-AutorunSettingSummary -Setting $autorunSetting),
        if ($autorunSetting -and $autorunSetting.Path) { " (from $($autorunSetting.Path))" } else { '' })) | Out-Null

    $registryEvidence = Build-AutorunEvidence -Entries $entries -Names @('NoDriveTypeAutoRun','NoAutoRun','NoAutorun')

    $evidenceParts = [System.Collections.Generic.List[string]]::new()
    if ($effectiveLines.Count -gt 0) {
        $evidenceParts.Add("Effective configuration:`n$($effectiveLines.ToArray() -join "`n")") | Out-Null
    }
    if ($registryEvidence) {
        $evidenceParts.Add("Registry snapshots:`n$registryEvidence") | Out-Null
    }
    $evidence = if ($evidenceParts.Count -gt 0) { $evidenceParts.ToArray() -join "`n`n" } else { $null }

    if ($driveCompliant -and $autorunCompliant) {
        Add-CategoryNormal -CategoryResult $CategoryResult -Title 'Autorun and Autoplay disabled via policy.' -Evidence $evidence -Subcategory 'Removable Media'
        return
    }

    $reasons = [System.Collections.Generic.List[string]]::new()
    if (-not $driveCompliant) {
        $reasons.Add(("{0} is {1}" -f $driveName, (Get-AutorunSettingSummary -Setting $driveSetting))) | Out-Null
    }
    if (-not $autorunCompliant) {
        $reasons.Add(("{0} is {1}" -f $autorunName, (Get-AutorunSettingSummary -Setting $autorunSetting))) | Out-Null
    }

    $reasonText = if ($reasons.Count -gt 0) { $reasons.ToArray() -join ' and ' } else { 'required registry values are not enforced' }
    $title = "Autorun/Autoplay remains enabled because {0}, so removable media may execute automatically." -f $reasonText

    Add-CategoryIssue -CategoryResult $CategoryResult -Severity 'medium' -Title $title -Evidence $evidence -Subcategory 'Removable Media'
}

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

function Add-UniqueDriverNameVariant {
    param(
        [System.Collections.Generic.List[string]]$List,
        [hashtable]$Lookup,
        [string]$Name
    )

    if (-not $List -or -not $Lookup) { return }
    if ([string]::IsNullOrWhiteSpace($Name)) { return }

    $trimmed = $Name.Trim(' `t`r`n.:;''"'.ToCharArray())
    if (-not $trimmed) { return }

    $candidates = [System.Collections.Generic.List[string]]::new()
    $candidates.Add($trimmed) | Out-Null

    $withoutSuffix = [regex]::Replace($trimmed, '\b(service|driver)\b$', '', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Trim(' `t`r`n.:;''"'.ToCharArray())
    if ($withoutSuffix -and ($withoutSuffix -ne $trimmed)) {
        $candidates.Add($withoutSuffix) | Out-Null
    }

    foreach ($candidate in @($trimmed, $withoutSuffix)) {
        if (-not $candidate) { continue }
        $dotIndex = $candidate.IndexOf('.')
        if ($dotIndex -gt 0) {
            $prefix = $candidate.Substring(0, $dotIndex)
            if ($prefix -and ($prefix -ne $candidate)) {
                $candidates.Add($prefix) | Out-Null
            }
        }
    }

    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        $lower = $candidate.ToLowerInvariant()
        if (-not $Lookup.ContainsKey($lower)) {
            $Lookup[$lower] = $true
            $List.Add($candidate) | Out-Null
        }
    }
}

function Parse-DriverQueryEntries {
    param(
        [string]$Text
    )

    $entries = New-Object System.Collections.Generic.List[pscustomobject]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $entries.ToArray() }

    $lines = $Text -split '\r?\n'
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

function Get-DriverNameCandidates {
    param($Entry)

    $list = [System.Collections.Generic.List[string]]::new()
    $lookup = @{}

    foreach ($name in @('Display Name','Module Name','Driver Name','Name','Service Name')) {
        $value = Get-DriverPropertyValue -Entry $Entry -Names @($name)
        if ($value) {
            Add-UniqueDriverNameVariant -List $list -Lookup $lookup -Name $value
        }
    }

    return $list.ToArray()
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

function Get-PnpDeviceLabel {
    param($Entry)

    $label = Get-DriverPropertyValue -Entry $Entry -Names @('Device Description','Friendly Name','Name','Instance ID','InstanceID')
    if ($label) { return $label }
    return 'Unknown device'
}

function Get-PnpDeviceEvidence {
    param($Entry)

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('Device Description','Instance ID','Class Name','Manufacturer Name','Status','Problem','Problem Status')) {
        $value = Get-DriverPropertyValue -Entry $Entry -Names @($name)
        if ($value) {
            $lines.Add(("{0}: {1}" -f $name, $value)) | Out-Null
        }
    }

    if ($lines.Count -eq 0) { return $null }
    return ($lines.ToArray() -join "`n")
}

function Normalize-PnpProblem {
    param(
        [string[]]$Values
    )

    if (-not $Values) { return 'unknown' }

    foreach ($value in $Values) {
        if (-not $value) { continue }
        $lower = $value.Trim().ToLowerInvariant()
        if (-not $lower) { continue }

        if ($lower -match '0x00000028' -or $lower -match '\bcode\s*28\b' -or $lower -match 'cm_prob_failed_install' -or $lower -match 'dn_driver_not_installed' -or $lower -match 'driver\s+not\s+install') {
            return 'missing-driver'
        }
        if ($lower -match 'cm_prob|problem|error') {
            return 'problem'
        }
    }

    return 'none'
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

function Normalize-DriverType {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -match 'kernel') { return 'kernel' }
    if ($lower -match 'file\s*system') { return 'filesystem' }
    if ($lower -match 'filter') { return 'filter' }
    if ($lower -match 'driver') { return 'driver' }
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
                $match = [regex]::Match($message, 'failed to load:\s*(?<names>.+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)
                if ($match.Success) {
                    $list = $match.Groups['names'].Value
                    if ($list) {
                        $tokens = $list -split '[\r\n,;]+'
                        foreach ($token in $tokens) {
                            if ([string]::IsNullOrWhiteSpace($token)) { continue }
                            $names.Add($token.Trim()) | Out-Null
                        }
                    }
                }
            }
        } elseif ($id -eq 7001) {
            if ($message) {
                $match = [regex]::Match($message, '^The\s+(?<primary>.+?)\s+(?:service|driver)\s+depends\s+on\s+the\s+(?<dependency>.+?)\s+(?:service|driver)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($match.Success) {
                    foreach ($groupName in @('primary','dependency')) {
                        $value = $match.Groups[$groupName].Value
                        if ($value) { $names.Add($value.Trim()) | Out-Null }
                    }
                } else {
                    $match = [regex]::Match($message, '^The\s+(?<name>.+?)\s+(?:service|driver)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    if ($match.Success) {
                        $value = $match.Groups['name'].Value
                        if ($value) { $names.Add($value.Trim()) | Out-Null }
                    }
                }
            }
        } else {
            if ($message) {
                $match = [regex]::Match($message, '^The\s+(?<name>.+?)\s+(?:service|driver)\s+failed\s+to\s+start', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
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
        $message = if ($event.Message) { [regex]::Replace([string]$event.Message, '\s+', ' ') } else { 'No message provided' }
        $lines.Add(("Event {0} at {1}: {2}" -f $event.Id, $time, $message.Trim())) | Out-Null
    }

    if ($lines.Count -eq 0) { return $null }
    return ($lines.ToArray() -join "`n")
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

    Invoke-AutorunPolicyAssessment -Context $Context -CategoryResult $result

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

    if ($payload.PnpProblems -and $payload.PnpProblems.PSObject.Properties['Error'] -and $payload.PnpProblems.Error) {
        $source = if ($payload.PnpProblems.PSObject.Properties['Source']) { [string]$payload.PnpProblems.Source } else { 'pnputil.exe' }
        $evidence = if ($payload.PnpProblems.Error) { [string]$payload.PnpProblems.Error } else { 'Unknown error' }
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Problem device inventory command failed, so Device Manager issues may be hidden." -Evidence ("{0}: {1}" -f $source, $evidence) -Subcategory 'Collection'
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

    $failureEventMap = Get-DriverFailureEventMap -Context $Context
    Write-HeuristicDebug -Source 'Hardware' -Message 'Loaded driver failure event map' -Data ([ordered]@{
        HasEvents = ($failureEventMap -and ($failureEventMap.Count -gt 0))
        Keys      = if ($failureEventMap) { $failureEventMap.Count } else { 0 }
    })

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
        $driverTypeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Driver Type','Type','Service Type')
        $driverTypeNormalized = Normalize-DriverType -Value $driverTypeRaw
        $shouldFlagStartIssue = $false
        $failureEvents = @()

        if ($startModeNormalized -in @('boot','system','auto') -and $stateNormalized -ne 'running' -and $stateNormalized -ne 'pending') {
            if ($startModeNormalized -eq 'auto') {
                $shouldFlagStartIssue = $true
            } elseif ($startModeNormalized -in @('boot','system')) {
                if ($driverTypeNormalized -eq 'kernel') {
                    $candidates = Get-DriverNameCandidates -Entry $entry
                    $failureEvents = Find-DriverFailureEvents -Candidates $candidates -Map $failureEventMap
                    if ($failureEvents -and $failureEvents.Count -gt 0) {
                        $shouldFlagStartIssue = $true
                    } else {
                        Write-HeuristicDebug -Source 'Hardware' -Message 'Skipping stopped boot/system kernel driver without corroborating events' -Data ([ordered]@{
                            Driver     = $label
                            StartMode  = $startModeRaw
                            State      = $stateRaw
                            DriverType = $driverTypeRaw
                        })
                    }
                } else {
                    $shouldFlagStartIssue = $true
                }
            }
        }

        if ($shouldFlagStartIssue) {
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

            $evidenceParts = New-Object System.Collections.Generic.List[string]
            $driverEvidence = Get-DriverEvidence -Entry $entry
            if ($driverEvidence) { $evidenceParts.Add($driverEvidence) | Out-Null }

            if ($failureEvents -and $failureEvents.Count -gt 0) {
                $eventEvidence = Format-DriverFailureEvidence -Events $failureEvents
                if ($eventEvidence) {
                    $evidenceParts.Add("Related events:`n$eventEvidence") | Out-Null
                }
            }

            $evidence = if ($evidenceParts.Count -gt 0) { $evidenceParts.ToArray() -join "`n`n" } else { $null }

            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidence -Subcategory 'Device Manager'
            $issueCount++
        }
    }

    $pnpText = ConvertTo-HardwareDriverText -Value $payload.PnpProblems
    Write-HeuristicDebug -Source 'Hardware' -Message 'Problem device text resolved' -Data ([ordered]@{
        HasText = [bool]$pnpText
        Length  = if ($pnpText) { $pnpText.Length } else { 0 }
    })

    if ($pnpText) {
        $pnpEntries = Parse-DriverQueryEntries -Text $pnpText
        Write-HeuristicDebug -Source 'Hardware' -Message 'Parsed problem device entries' -Data ([ordered]@{
            EntryCount = $pnpEntries.Count
        })

        foreach ($entry in $pnpEntries) {
            if (-not $entry) { continue }

            $label = Get-PnpDeviceLabel -Entry $entry
            $statusRaw = Get-DriverPropertyValue -Entry $entry -Names @('Status','Problem Status')
            $problemRaw = Get-DriverPropertyValue -Entry $entry -Names @('Problem','Problem Code','ProblemStatus')
            $normalized = Normalize-PnpProblem -Values @($statusRaw, $problemRaw)

            if ($normalized -eq 'missing-driver') {
                $title = "Device {0} is missing drivers (Code 28), so functionality may be limited." -f $label
                Add-CategoryIssue -CategoryResult $result -Severity 'medium' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
                continue
            }

            if ($normalized -eq 'problem') {
                $title = "Device Manager reports a problem for {0}." -f $label
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title $title -Evidence (Get-PnpDeviceEvidence -Entry $entry) -Subcategory 'Device Manager'
                $issueCount++
            }
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
