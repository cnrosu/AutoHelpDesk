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

function ConvertTo-NullableBool {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }

    if ($Value -is [int]) {
        if ($Value -eq 1) { return $true }
        if ($Value -eq 0) { return $false }
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $normalized = $text.Trim().ToLowerInvariant()
    switch ($normalized) {
        'true'     { return $true }
        'false'    { return $false }
        '1'        { return $true }
        '0'        { return $false }
        'yes'      { return $true }
        'no'       { return $false }
        'enabled'  { return $true }
        'disabled' { return $false }
        default    { return $null }
    }
}

function Get-HardwareDriverFailureEvents {
    param($Context)

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'events'
    if (-not $artifact) { return @() }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) { return @() }

    if (-not ($payload.PSObject.Properties['System'])) { return @() }
    $systemNode = $payload.System
    if (-not $systemNode) { return @() }
    if ($systemNode.PSObject.Properties['Error'] -and $systemNode.Error) { return @() }

    $items = @()
    if ($systemNode -is [System.Collections.IEnumerable] -and -not ($systemNode -is [string])) {
        $items = @($systemNode)
    } else {
        $items = @($systemNode)
    }

    $events = New-Object System.Collections.Generic.List[object]
    foreach ($item in $items) {
        if (-not $item) { continue }
        if (-not ($item.PSObject.Properties['Id'])) { continue }
        $id = $item.Id
        if ($null -eq $id) { continue }
        try { $idValue = [int]$id } catch { continue }
        if ($idValue -in 7000, 7001, 7026) {
            $events.Add($item) | Out-Null
        }
    }

    return $events.ToArray()
}

function Test-HardwareEventMatchesDriver {
    param(
        $Event,
        [string[]]$CandidateNames
    )

    if (-not $Event -or -not $CandidateNames -or $CandidateNames.Count -eq 0) { return $false }

    $message = $null
    if ($Event.PSObject.Properties['Message']) {
        $message = [string]$Event.Message
    }
    if (-not $message) { return $false }

    foreach ($name in $CandidateNames) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $pattern = [regex]::Escape($name.Trim())
        if (-not $pattern) { continue }
        if ([regex]::IsMatch($message, "(?i)(^|[^A-Za-z0-9_])$pattern([^A-Za-z0-9_]|$)")) {
            return $true
        }
    }

    return $false
}

function ConvertTo-DriverEventEvidence {
    param($Event)

    if (-not $Event) { return $null }

    $parts = New-Object System.Collections.Generic.List[string]
    if ($Event.PSObject.Properties['TimeCreated'] -and $Event.TimeCreated) {
        $parts.Add(("Time: {0}" -f $Event.TimeCreated)) | Out-Null
    }
    if ($Event.PSObject.Properties['Id'] -and $Event.Id -ne $null) {
        $parts.Add(("Event ID: {0}" -f $Event.Id)) | Out-Null
    }
    if ($Event.PSObject.Properties['ProviderName'] -and $Event.ProviderName) {
        $parts.Add(("Source: {0}" -f $Event.ProviderName)) | Out-Null
    }
    if ($Event.PSObject.Properties['Message'] -and $Event.Message) {
        $message = [string]$Event.Message
        if ($message) {
            $normalized = ($message -replace '\r?\n', ' ')
            if ($normalized.Length -gt 220) {
                $normalized = $normalized.Substring(0, 220) + '…'
            }
            $parts.Add(("Message: {0}" -f $normalized)) | Out-Null
        }
    }

    if ($parts.Count -eq 0) { return $null }
    return ($parts.ToArray() -join '; ')
}

function Get-HardwareDefenderStatus {
    param($Context)

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'defender'
    if (-not $artifact) { return $null }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) { return $null }

    if (-not ($payload.PSObject.Properties['Status'])) { return $null }
    $status = $payload.Status
    if (-not $status) { return $null }
    if ($status.PSObject.Properties['Error'] -and $status.Error) { return $null }

    return [pscustomobject]@{
        AMServiceEnabled          = ConvertTo-NullableBool $status.AMServiceEnabled
        AntivirusEnabled          = ConvertTo-NullableBool $status.AntivirusEnabled
        RealTimeProtectionEnabled = ConvertTo-NullableBool $status.RealTimeProtectionEnabled
    }
}

function Get-HardwareDefenderActiveState {
    param($Status)

    if (-not $Status) { return $null }

    $values = New-Object System.Collections.Generic.List[bool]
    foreach ($property in @('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled')) {
        if (-not $Status.PSObject.Properties[$property]) { continue }
        $value = $Status.$property
        if ($null -eq $value) { continue }
        try {
            $boolValue = [bool]$value
            if ($boolValue -eq $true) {
                $values.Add($true) | Out-Null
            } elseif ($boolValue -eq $false) {
                $values.Add($false) | Out-Null
            }
        } catch {
        }
    }

    if ($values.Count -eq 0) { return $null }
    if ($values.Contains($true)) { return $true }
    if ($values.Contains($false) -and -not $values.Contains($true)) { return $false }
    return $null
}

function Get-DriverStartupAssessment {
    param(
        [pscustomobject]$DriverInfo,
        [object[]]$FailureEvents,
        [hashtable]$DriverLookup,
        $DefenderStatus
    )

    $result = [ordered]@{
        ShouldReport = $false
        Severity     = $null
        Evidence     = @()
        Reason       = $null
    }

    if (-not $DriverInfo) { return [pscustomobject]$result }

    $startMode = $DriverInfo.StartModeNormalized
    $baseSeverity = if ($startMode -in @('boot','system')) { 'high' } else { 'medium' }
    if ($DriverInfo.ErrorControlNormalized -eq 'critical') { $baseSeverity = 'critical' }

    $candidateNames = New-Object System.Collections.Generic.List[string]
    if ($DriverInfo.ModuleName) { $candidateNames.Add([string]$DriverInfo.ModuleName) | Out-Null }
    if ($DriverInfo.Label -and $DriverInfo.Label -ne 'Unknown driver') { $candidateNames.Add([string]$DriverInfo.Label) | Out-Null }

    $matchedEvents = New-Object System.Collections.Generic.List[object]
    foreach ($event in $FailureEvents) {
        if (Test-HardwareEventMatchesDriver -Event $event -CandidateNames $candidateNames.ToArray()) {
            $matchedEvents.Add($event) | Out-Null
        }
    }

    if ($matchedEvents.Count -gt 0) {
        $evidenceLines = New-Object System.Collections.Generic.List[string]
        foreach ($event in ($matchedEvents.ToArray() | Select-Object -First 3)) {
            $line = ConvertTo-DriverEventEvidence -Event $event
            if ($line) { $evidenceLines.Add($line) | Out-Null }
        }

        $result.ShouldReport = $true
        $result.Severity = $baseSeverity
        $result.Evidence = $evidenceLines.ToArray()
        $result.Reason = 'Service Control Manager failure event detected for driver'
        return [pscustomobject]$result
    }

    if ($startMode -in @('boot','system')) {
        $moduleKey = $null
        if ($DriverInfo.ModuleName) { $moduleKey = $DriverInfo.ModuleName.ToLowerInvariant() }

        $reason = 'No Service Control Manager failure events detected for boot/system driver'
        if ($moduleKey -eq 'wdboot') {
            $wdFilterRunning = $false
            if ($DriverLookup -and $DriverLookup.ContainsKey('wdfilter')) {
                $wdFilterInfo = $DriverLookup['wdfilter']
                if ($wdFilterInfo -and $wdFilterInfo.StateNormalized -eq 'running') { $wdFilterRunning = $true }
            }

            $defenderActive = Get-HardwareDefenderActiveState -Status $DefenderStatus
            if ($wdFilterRunning -and ($defenderActive -eq $true -or $defenderActive -eq $null)) {
                $reason = 'WdBoot expected to stop after handing off to WdFilter when Defender is active.'
            } elseif (-not $wdFilterRunning -and $defenderActive -eq $false) {
                $reason = 'WdBoot inactive with Defender disabled; no failure evidence present.'
            } else {
                $reason = 'WdBoot reported stopped but no corroborating failure signals were detected.'
            }
        } elseif ($moduleKey -in @('dam','hwpolicy')) {
            $reason = 'Common boot/system driver stops post-boot without indicating a fault.'
        }

        $result.Reason = $reason
        return [pscustomobject]$result
    }

    $result.ShouldReport = $true
    $result.Severity = $baseSeverity
    $result.Reason = 'Automatic-start driver stopped without corroborating events.'
    return [pscustomobject]$result
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

    $failureEvents = Get-HardwareDriverFailureEvents -Context $Context
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved Service Control Manager failure events for driver analysis' -Data ([ordered]@{
        FailureEventCount = if ($failureEvents) { $failureEvents.Count } else { 0 }
    })

    $defenderStatus = Get-HardwareDefenderStatus -Context $Context
    Write-HeuristicDebug -Source 'Hardware' -Message 'Resolved Defender status for driver heuristics' -Data ([ordered]@{
        HasStatus               = [bool]$defenderStatus
        AMServiceEnabled        = if ($defenderStatus) { $defenderStatus.AMServiceEnabled } else { $null }
        AntivirusEnabled        = if ($defenderStatus) { $defenderStatus.AntivirusEnabled } else { $null }
        RealTimeProtection      = if ($defenderStatus) { $defenderStatus.RealTimeProtectionEnabled } else { $null }
    })

    $driverInfos = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($entry in $entries) {
        if (-not $entry) { continue }

        $label = Get-DriverLabel -Entry $entry
        $statusRaw = Get-DriverPropertyValue -Entry $entry -Names @('Status')
        $statusNormalized = Normalize-DriverStatus -Value $statusRaw
        $stateRaw = Get-DriverPropertyValue -Entry $entry -Names @('State')
        $startModeRaw = Get-DriverPropertyValue -Entry $entry -Names @('Start Mode','StartMode')
        $stateNormalized = Normalize-DriverState -Value $stateRaw
        $startModeNormalized = Normalize-DriverStartMode -Value $startModeRaw
        $errorControlRaw = Get-DriverPropertyValue -Entry $entry -Names @('Error Control','ErrorControl')
        $errorControlNormalized = Normalize-DriverErrorControl -Value $errorControlRaw
        $moduleName = Get-DriverPropertyValue -Entry $entry -Names @('Module Name','Driver Name','Name')

        $driverInfos.Add([pscustomobject]@{
            Entry                  = $entry
            Label                  = $label
            StatusRaw              = $statusRaw
            StatusNormalized       = $statusNormalized
            StateRaw               = $stateRaw
            StateNormalized        = $stateNormalized
            StartModeRaw           = $startModeRaw
            StartModeNormalized    = $startModeNormalized
            ErrorControlRaw        = $errorControlRaw
            ErrorControlNormalized = $errorControlNormalized
            ModuleName             = $moduleName
        }) | Out-Null
    }

    $driverLookup = @{}
    foreach ($info in $driverInfos) {
        if (-not $info.ModuleName) { continue }
        $key = $info.ModuleName.ToLowerInvariant()
        if (-not $key) { continue }
        if (-not $driverLookup.ContainsKey($key)) {
            $driverLookup[$key] = $info
        }
    }

    $issueCount = 0
    foreach ($info in $driverInfos) {
        if (-not $info) { continue }

        $entry = $info.Entry
        $label = $info.Label

        $statusNormalized = $info.StatusNormalized
        if ($statusNormalized -and $statusNormalized -ne 'ok' -and $statusNormalized -ne 'unknown') {
            $severity = switch ($statusNormalized) {
                'error'    { 'high' }
                'degraded' { 'medium' }
                default    { 'info' }
            }
            $title = if ($info.StatusRaw) {
                "Driver status '{0}' reported for {1}, so the device may malfunction." -f $info.StatusRaw, $label
            } else {
                "Driver status indicates an issue for {0}, so the device may malfunction." -f $label
            }
            Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence (Get-DriverEvidence -Entry $entry) -Subcategory 'Device Manager'
            $issueCount++
        }

        if ($info.StartModeNormalized -in @('boot','system','auto') -and $info.StateNormalized -ne 'running' -and $info.StateNormalized -ne 'pending') {
            $assessment = Get-DriverStartupAssessment -DriverInfo $info -FailureEvents $failureEvents -DriverLookup $driverLookup -DefenderStatus $defenderStatus
            Write-HeuristicDebug -Source 'Hardware' -Message 'Driver startup assessment' -Data ([ordered]@{
                Driver        = if ($info.ModuleName) { $info.ModuleName } else { $label }
                StartMode     = $info.StartModeNormalized
                ShouldReport  = $assessment.ShouldReport
                Reason        = $assessment.Reason
                EvidenceCount = if ($assessment.Evidence) { (@($assessment.Evidence)).Count } else { 0 }
                Severity      = if ($assessment.Severity) { $assessment.Severity } else { '(default)' }
            })

            if ($assessment.ShouldReport) {
                $severity = if ($assessment.Severity) {
                    $assessment.Severity
                } elseif ($info.StartModeNormalized -in @('boot','system')) {
                    'high'
                } else {
                    'medium'
                }

                $title = if ($info.StateRaw -and $info.StartModeRaw) {
                    "Driver {0} is {1} despite start mode {2}, so hardware may not initialize." -f $label, $info.StateRaw, $info.StartModeRaw
                } elseif ($info.StartModeRaw) {
                    "Driver {0} is not running despite start mode {1}, so hardware may not initialize." -f $label, $info.StartModeRaw
                } else {
                    "Driver {0} is not running despite an automatic start mode, so hardware may not initialize." -f $label
                }

                $evidenceLines = New-Object System.Collections.Generic.List[string]
                if ($assessment.Evidence) {
                    foreach ($line in @($assessment.Evidence)) {
                        if (-not $line) { continue }
                        $evidenceLines.Add([string]$line) | Out-Null
                    }
                }
                $driverEvidence = Get-DriverEvidence -Entry $entry
                if ($driverEvidence) { $evidenceLines.Add($driverEvidence) | Out-Null }
                $evidenceText = if ($evidenceLines.Count -gt 0) { ($evidenceLines.ToArray() -join "`n") } else { $null }

                Add-CategoryIssue -CategoryResult $result -Severity $severity -Title $title -Evidence $evidenceText -Subcategory 'Device Manager'
                $issueCount++
            }
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
