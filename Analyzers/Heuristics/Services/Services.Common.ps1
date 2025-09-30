function Normalize-ServiceStateValue {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    if ($lower -like 'run*') { return 'running' }
    if ($lower -like 'stop*') { return 'stopped' }
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
    if ($lower -like 'manual*') { return 'manual' }
    if ($lower -like 'disabled*') { return 'disabled' }
    return 'other'
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

    if (-not $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value)
    }

    return @($Value)
}

function ConvertTo-ServiceErrorMessages {
    param($Value)

    $messages = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Value) { return $messages.ToArray() }

    $queue = [System.Collections.Queue]::new()
    $null = $queue.Enqueue($Value)

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        if ($null -eq $current) { continue }

        if (
            $current -is [System.Collections.IEnumerable] -and
            -not ($current -is [string]) -and
            -not ($current -is [System.Collections.IDictionary])
        ) {
            foreach ($item in $current) {
                $null = $queue.Enqueue($item)
            }
            continue
        }

        $text = $null

        if ($current -is [System.Management.Automation.ErrorRecord]) {
            if ($current.Exception -and $current.Exception.Message) {
                $text = [string]$current.Exception.Message
            } else {
                $text = [string]$current.ToString()
            }
        } elseif ($current.PSObject -and $current.PSObject.Properties['Message']) {
            $text = [string]$current.Message
        } elseif ($current.PSObject -and $current.PSObject.Properties['Exception']) {
            $exception = $current.Exception
            if ($exception -and $exception.Message) {
                $text = [string]$exception.Message
            } elseif ($exception) {
                $text = [string]$exception.ToString()
            }
        }

        if (-not $text) {
            $text = [string]$current
        }

        if (-not [string]::IsNullOrWhiteSpace($text)) {
            $null = $messages.Add($text.Trim())
        }
    }

    return $messages.ToArray()
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
    $systemArtifact = Get-AnalyzerArtifact -Context $Context -Name 'system'
    if ($systemArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $systemArtifact)
        if ($payload -and $payload.OperatingSystem -and -not $payload.OperatingSystem.Error) {
            $caption = [string]$payload.OperatingSystem.Caption
            if ($caption) {
                $isWindowsServer = ($caption -match '(?i)windows\s+server')
            }
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
