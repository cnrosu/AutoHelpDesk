function Normalize-ServiceStateValue {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    if ($lower -like 'run*') { return 'running' }
    if ($lower -like 'stop*') { return 'stopped' }
    if ($lower -like 'pause*' -or $lower -like 'pending*') { return 'other' }
    return 'other'
}

function Normalize-ServiceStartValue {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    if ($lower -like 'auto*' -and $lower -like '*delay*') { return 'automatic-delayed' }
    if ($lower -like 'auto*') { return 'automatic' }
    if ($lower -like 'manual*' -or $lower -like 'demand*') { return 'manual' }
    if ($lower -like 'disabled*') { return 'disabled' }
    if ($lower -like 'boot*' -or $lower -like 'system*') { return 'other' }
    return 'other'
}

function Resolve-ServicePropertyValue {
    param(
        $Service,
        [string[]]$Names
    )

    if (-not $Service) { return $null }

    foreach ($name in $Names) {
        if (-not $name) { continue }
        if ($Service.PSObject.Properties[$name]) {
            $value = $Service.$name
            if ($null -ne $value) {
                $stringValue = [string]$value
                if (-not [string]::IsNullOrWhiteSpace($stringValue)) {
                    return $stringValue.Trim()
                }
            }
        }
    }

    return $null
}

function Expand-NormalizedServiceState {
    param([string]$Value)

    if (-not $Value) { return $null }

    switch ($Value.ToLowerInvariant()) {
        'running' { return 'Running' }
        'stopped' { return 'Stopped' }
        'other'   { return 'Other' }
        'unknown' { return 'Unknown' }
        default   { return $Value }
    }
}

function Expand-NormalizedStartValue {
    param([string]$Value)

    if (-not $Value) { return $null }

    switch ($Value.ToLowerInvariant()) {
        'automatic-delayed' { return 'Automatic (Delayed)' }
        'automatic'         { return 'Automatic' }
        'manual'            { return 'Manual' }
        'disabled'          { return 'Disabled' }
        'unknown'           { return 'Unknown' }
        default             { return $Value }
    }
}

function Get-ServiceStateInfo {
    param(
        $Lookup,
        [string]$Name
    )

    if (-not $Lookup -or -not $Lookup.ContainsKey($Name)) {
        return [pscustomobject]@{
            Exists              = $false
            Name                = $Name
            DisplayName         = $Name
            Status              = 'Unknown'
            StatusNormalized    = 'unknown'
            StartMode           = 'Unknown'
            StartModeNormalized = 'unknown'
        }
    }

    $service = $Lookup[$Name]
    $status = 'Unknown'
    if ($service.PSObject.Properties['State']) { $status = [string]$service.State }
    elseif ($service.PSObject.Properties['Status']) { $status = [string]$service.Status }

    $startMode = 'Unknown'
    if ($service.PSObject.Properties['StartMode']) { $startMode = [string]$service.StartMode }
    elseif ($service.PSObject.Properties['StartType']) { $startMode = [string]$service.StartType }

    $displayName = if ($service.PSObject.Properties['DisplayName']) { [string]$service.DisplayName } else { $Name }

    return [pscustomobject]@{
        Exists              = $true
        Name                = $Name
        DisplayName         = $displayName
        Status              = if ($status) { $status } else { 'Unknown' }
        StatusNormalized    = Normalize-ServiceStateValue -Value $status
        StartMode           = if ($startMode) { $startMode } else { 'Unknown' }
        StartModeNormalized = Normalize-ServiceStartValue -Value $startMode
    }
}

function ConvertTo-ServiceCollection {
    param($Value)

    $items = @()
    if (-not $Value) {
        $items = @()
    } elseif ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @($Value)
    } else {
        $items = @($Value)
    }

    $normalized = New-Object System.Collections.Generic.List[pscustomobject]
    $metrics = [ordered]@{
        SourceCount          = $items.Count
        MissingName          = 0
        MissingStatus        = 0
        MissingStartType     = 0
        UsedNormalizedStatus = 0
        UsedNormalizedStart  = 0
    }

    foreach ($service in $items) {
        if (-not $service) { continue }

        $name = Resolve-ServicePropertyValue -Service $service -Names @('Name','ServiceName','Key','Id')
        if (-not $name) {
            $metrics.MissingName++
            continue
        }

        $displayName = Resolve-ServicePropertyValue -Service $service -Names @('DisplayName','ServiceDisplayName','Caption')

        $statusSource = Resolve-ServicePropertyValue -Service $service -Names @('Status','State','CurrentState','ServiceState')
        $usedNormalizedStatus = $false
        if (-not $statusSource) {
            $normalizedStatusValue = Resolve-ServicePropertyValue -Service $service -Names @('NormalizedStatus','StatusNormalized')
            if ($normalizedStatusValue) {
                $statusSource = Expand-NormalizedServiceState -Value $normalizedStatusValue
                $usedNormalizedStatus = $true
            }
        }
        if (-not $statusSource) {
            $metrics.MissingStatus++
            $statusSource = 'Unknown'
        } elseif ($usedNormalizedStatus) {
            $metrics.UsedNormalizedStatus++
        }

        $startSource = Resolve-ServicePropertyValue -Service $service -Names @('StartType','StartMode','StartUpType','StartupType','StartModeDisplay')
        $usedNormalizedStart = $false
        if (-not $startSource) {
            $normalizedStart = Resolve-ServicePropertyValue -Service $service -Names @('NormalizedStartType','StartTypeNormalized','StartModeNormalized')
            if ($normalizedStart) {
                $startSource = Expand-NormalizedStartValue -Value $normalizedStart
                $usedNormalizedStart = $true
            }
        }
        if (-not $startSource) {
            $metrics.MissingStartType++
            $startSource = 'Unknown'
        } elseif ($usedNormalizedStart) {
            $metrics.UsedNormalizedStart++
        }

        $stateValue = Resolve-ServicePropertyValue -Service $service -Names @('State','Status','CurrentState','ServiceState')
        if (-not $stateValue) { $stateValue = $statusSource }

        $normalizedStatus = Normalize-ServiceStateValue -Value $statusSource
        $normalizedStart = Normalize-ServiceStartValue -Value $startSource

        $entry = [ordered]@{
            Name                 = $name
            DisplayName          = if ($displayName) { $displayName } else { $name }
            Status               = $statusSource
            State                = $stateValue
            StartMode            = $startSource
            StartType            = $startSource
            StatusNormalized     = $normalizedStatus
            NormalizedStatus     = $normalizedStatus
            StartModeNormalized  = $normalizedStart
            NormalizedStartType  = $normalizedStart
            Raw                  = $service
        }

        $normalized.Add([pscustomobject]$entry) | Out-Null
    }

    return [pscustomobject]@{
        Services = $normalized
        Metrics  = $metrics
    }
}

function New-ServiceLookup {
    param([array]$Services)

    $lookup = @{}
    foreach ($service in $Services) {
        if (-not $service) { continue }
        if ($service.PSObject.Properties['Name']) {
            $lookup[[string]$service.Name] = $service
        }
    }

    return $lookup
}

function Get-DevicePlatformInfo {
    param($Context)

    Write-HeuristicDebug -Source 'Services/Common' -Message 'Determining device platform'

    $isWindowsServer = $null
    $msinfoIdentity = Get-MsinfoSystemIdentity -Context $Context
    if ($msinfoIdentity -and $msinfoIdentity.PSObject.Properties['OSName']) {
        $caption = [string]$msinfoIdentity.OSName
        if ($caption) {
            $isWindowsServer = ($caption -match '(?i)windows\s+server')
        }
    }

    $isWorkstation = $null
    if ($isWindowsServer -eq $true) { $isWorkstation = $false }
    elseif ($isWindowsServer -eq $false) { $isWorkstation = $true }

    return [pscustomobject]@{
        IsWindowsServer = $isWindowsServer
        IsWorkstation   = $isWorkstation
    }
}

function Get-SystemProxyInfo {
    param($Context)

    Write-HeuristicDebug -Source 'Services/Common' -Message 'Evaluating system proxy configuration'

    $hasSystemProxy = $false
    $proxyEvidence = $null

    $proxyArtifact = Get-AnalyzerArtifact -Context $Context -Name 'proxy'
    if ($proxyArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $proxyArtifact)
        if ($payload -and $payload.WinHttp) {
            if ($payload.WinHttp -is [System.Collections.IEnumerable] -and -not ($payload.WinHttp -is [string])) {
                $proxyEvidence = ($payload.WinHttp -join "`n").Trim()
            } else {
                $proxyEvidence = ([string]$payload.WinHttp).Trim()
            }

            if ($proxyEvidence -and ($proxyEvidence -notmatch '(?i)direct\s+access')) {
                $hasSystemProxy = $true
            }
        }
    }

    return [pscustomobject]@{
        HasSystemProxy = $hasSystemProxy
        Evidence       = $proxyEvidence
    }
}
